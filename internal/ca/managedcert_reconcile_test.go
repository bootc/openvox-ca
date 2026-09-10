// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

// White-box, for the reason renewrace_test.go and supersederace_test.go both
// give: these specs hold the very lock the code under test must acquire, and
// subjectLockName is the only thing that knows what it is called. Spelling the
// string a second time from outside would let a spec hold the wrong lock, block
// nothing, and still pass.
package ca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// memStore is a managed certificate's store, in memory. It is deliberately not
// an implementation of an interface: ManagedCert takes two functions, so a
// caller's store is whatever pair of closures it cares to supply, and this is
// one such pair.
type memStore struct {
	mu      sync.Mutex
	certPEM []byte
	keyPEM  []byte

	saves   int
	loadErr error
	saveErr error

	// delay is spent inside Load, before anything is returned. It exists for
	// the convergence specs: it widens the window in which four replicas are
	// all holding stale material, which is what makes the unlocked outcome a
	// certainty rather than a likelihood. Under a shared lock it costs one
	// delay per replica and changes no outcome.
	delay time.Duration
}

func (s *memStore) load(context.Context) ([]byte, []byte, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return nil, nil, s.loadErr
	}
	return s.certPEM, s.keyPEM, nil
}

func (s *memStore) save(_ context.Context, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	s.certPEM, s.keyPEM = certPEM, keyPEM
	s.saves++
	return nil
}

// stored returns the certificate currently in the store, parsed.
func (s *memStore) stored() *x509.Certificate {
	GinkgoHelper()
	s.mu.Lock()
	defer s.mu.Unlock()
	block, _ := pem.Decode(s.certPEM)
	Expect(block).NotTo(BeNil(), "the store holds no certificate")
	crt, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return crt
}

func (s *memStore) saveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saves
}

var _ = Describe("Reconciling a managed certificate", func() {
	const subject = "managed.test"

	var (
		ctx      context.Context
		storeDir string
		store    *storage.StorageService
		myCA     *CA
		spec     CertSpec
		fake     *memStore
		entry    ManagedCert
	)

	BeforeEach(func() {
		ctx = context.Background()
		storeDir = GinkgoT().TempDir()
		store = storage.New(storeDir)
		myCA = New(store, AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		spec = CertSpec{
			Subject:     subject,
			DNSNames:    []string{subject, "managed"},
			TTL:         90 * 24 * time.Hour,
			RenewBefore: 30 * 24 * time.Hour,
		}
		fake = &memStore{}
		entry = ManagedCert{Spec: spec, Load: fake.load, Save: fake.save}
	})

	reconcile := func() (bool, error) {
		return myCA.reconcileManagedCert(ctx, entry, time.Now().UTC())
	}

	// reconcileAt runs a pass as though it were `ahead` from now. It is how the
	// specs below reach a *second* issuance, and the honest way to do it: the
	// obvious alternative -- widening RenewBefore until the certificate falls
	// inside it -- cannot work, because renewWindowFor clamps the window to
	// half the certificate's forward life precisely so that no setting can make
	// a fresh certificate due. Ageing the clock is what a real deployment does.
	reconcileAt := func(ahead time.Duration) (bool, error) {
		return myCA.reconcileManagedCert(ctx, entry, time.Now().UTC().Add(ahead))
	}

	// dueWindow is far enough ahead that a 90-day certificate is inside its
	// 30-day renew window, and short enough that it has not expired.
	const dueWindow = 80 * 24 * time.Hour

	Describe("the first pass", func() {
		It("issues, and writes the pair to the store", func() {
			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())

			crt := fake.stored()
			Expect(crt.Subject.CommonName).To(Equal(subject))
			Expect(crt.DNSNames).To(ConsistOf(subject, "managed"))
			Expect(fake.keyPEM).NotTo(BeEmpty(), "the certificate is useless without its key")
		})

		It("records the certificate the way every other issuance does", func() {
			// A managed certificate is an ordinary certificate in every respect
			// that matters to the CA: a blob at cert/<subject>, an inventory
			// row, a serial-index entry. That is what makes it visible to
			// `list`, to OCSP, to the CRL and to the expiry sweep without any
			// of them being taught about it -- and it is why #178 was closed
			// rather than generalised.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())

			Expect(store.HasCert(ctx, subject)).To(BeTrue())
			stored, err := store.GetCert(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(stored).To(Equal(fake.certPEM),
				"the CA's own copy must be the certificate the store was given")

			serial, err := store.LatestSerialForSubject(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(serial).To(Equal(serialHexStr(fake.stored().SerialNumber)),
				"the inventory row must name the certificate that was issued")
		})

		It("leaves no private key behind, in the backing store or the cadir", func() {
			// The invariant this mechanism exists to preserve. POST /generate
			// still writes leaf keys to <cadir>/private/ and is unchanged; a
			// managed certificate's key goes to its own store and nowhere else.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())

			_, statErr := os.Stat(store.PrivateKeyPath(subject))
			Expect(os.IsNotExist(statErr)).To(BeTrue(),
				"a managed certificate's key must not be written to the cadir")

			entries, err := os.ReadDir(filepath.Join(storeDir, "private"))
			if err == nil {
				for _, e := range entries {
					Expect(e.Name()).NotTo(ContainSubstring(subject))
				}
			}
		})
	})

	It("does nothing on a second pass", func() {
		issued, err := reconcile()
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeTrue())
		first := fake.stored().SerialNumber

		issued, err = reconcile()
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeFalse(), "a certificate that satisfies its spec must not be reissued")
		Expect(fake.saveCount()).To(Equal(1))
		Expect(fake.stored().SerialNumber).To(Equal(first))
	})

	It("issues a serverAuth-only certificate when the spec says so", func() {
		// SECURITY: the serving certificate must not be usable as a client
		// credential. A clientAuth certificate for a name that appears in
		// puppet_server is an admin credential, so this asserts the absence
		// rather than only the presence.
		entry.Spec.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		_, err := reconcile()
		Expect(err).NotTo(HaveOccurred())

		Expect(fake.stored().ExtKeyUsage).To(Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
		Expect(fake.stored().ExtKeyUsage).NotTo(ContainElement(x509.ExtKeyUsageClientAuth),
			"a serverAuth-only spec that still emitted clientAuth would hand out an admin credential")
	})

	It("issues the default usages when the spec names none", func() {
		// The other half: an omitted EKU must not mean "unrestricted", which is
		// what an empty ExtKeyUsage means in X.509.
		_, err := reconcile()
		Expect(err).NotTo(HaveOccurred())
		Expect(fake.stored().ExtKeyUsage).To(ConsistOf(
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth))
	})

	It("refuses an entry whose spec would not validate, without touching the store", func() {
		entry.Spec.RenewBefore = 0
		issued, err := reconcile()
		Expect(err).To(MatchError(ContainSubstring("renew_before must be positive")))
		Expect(issued).To(BeFalse())
		Expect(fake.saveCount()).To(BeZero())
	})

	It("stops on a store it cannot read rather than reissuing over it", func() {
		// Reconciling against material we could not read would reissue on every
		// pass for as long as the store is down -- and each pass would supersede
		// the last certificate it could not see.
		fake.loadErr = fmt.Errorf("backend unavailable")
		issued, err := reconcile()
		Expect(err).To(MatchError(ContainSubstring("backend unavailable")))
		Expect(issued).To(BeFalse())
		Expect(store.HasCert(ctx, subject)).To(BeFalse(), "nothing may be signed on this path")
	})

	Describe("when the store write fails after signing", func() {
		var predecessor *x509.Certificate

		BeforeEach(func() {
			// A first pass that succeeds, so there is a predecessor whose fate
			// the failure below is about.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			predecessor = fake.stored()

			// Make the store refuse the write. The passes below run ahead of
			// the clock so the predecessor is genuinely inside its window.
			fake.saveErr = fmt.Errorf("secret rejected")
		})

		It("revokes the certificate it just issued, immediately", func() {
			// Nothing ever saw this key: it was generated inside the lock and
			// the store refused it. A supersession window exists to let relying
			// parties pick up a replacement, and here there are none -- so this
			// is the one issuance retired without one, whatever SupersedeAfter
			// says.
			myCA.SupersedeAfter = 24 * time.Hour

			issued, err := reconcileAt(dueWindow)
			Expect(err).To(MatchError(ContainSubstring("secret rejected")))
			Expect(issued).To(BeFalse())

			stored, err := store.GetCert(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(stored)
			Expect(block).NotTo(BeNil())
			orphan, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(orphan.SerialNumber).NotTo(Equal(predecessor.SerialNumber),
				"the fixture is only meaningful if a new certificate was actually signed")

			revoked, err := myCA.IsRevokedSerial(ctx, orphan.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue(),
				"a certificate nobody can use must not be left live for its full lifetime")

			// And not merely recorded for later: an immediate revocation is on
			// the CRL now, with nothing waiting on a sweep.
			entries, _, rerr := myCA.readSuperseded(ctx)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty())
		})

		It("leaves the predecessor valid and in the store", func() {
			_, err := reconcileAt(dueWindow)
			Expect(err).To(HaveOccurred())

			Expect(fake.stored().SerialNumber).To(Equal(predecessor.SerialNumber),
				"the store must still hold the working pair it had before")
			revoked, err := myCA.IsRevokedSerial(ctx, predecessor.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(),
				"the predecessor is the only usable credential left; revoking it would strand the subject")
		})
	})

	Describe("retiring the predecessor", func() {
		It("records it for delayed revocation when a window is configured", func() {
			myCA.SupersedeAfter = 24 * time.Hour

			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			predecessor := fake.stored()

			issued, err := reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())

			revoked, err := myCA.IsRevokedSerial(ctx, predecessor.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(), "the window is the whole point: it must not be on the CRL yet")

			entries, _, err := myCA.readSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Serial).To(Equal(serialHexStr(predecessor.SerialNumber)))
			// The subject on the list is functional, not decorative:
			// retireSupersededForSubjectLocked matches it by exact string
			// equality, so a different spelling here silently loses this
			// predecessor from `revoke --certname`.
			Expect(entries[0].Subject).To(Equal(subject))
		})

		It("revokes it inline when no window is configured", func() {
			// SupersedeAfter's zero value. A CA constructed anywhere but
			// `openvox-ca serve` has it, so this is the behaviour a managed
			// certificate gets by default rather than an exotic setting.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			predecessor := fake.stored()

			_, err = reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())

			revoked, err := myCA.IsRevokedSerial(ctx, predecessor.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue())
		})

		It("does not put a foreign certificate's serial on our CRL", func() {
			// The store held something this CA did not issue. Replacing it is
			// right; revoking it is not ours to do, and the serial identifies a
			// different certificate under a different issuer.
			foreign, foreignKey := selfSignedIssuer("Some other CA")
			leaf := mintLeaf(foreign, foreignKey, subject, spec.DNSNames, nil,
				90*24*time.Hour, time.Now().UTC())
			fake.certPEM, fake.keyPEM = leaf.certPEM, leaf.keyPEM

			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())

			revoked, err := myCA.IsRevokedSerial(ctx, leaf.cert.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse())

			entries, _, err := myCA.readSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty())
		})
	})

	It("blocks on the subject lock the rest of the CA uses", func() {
		// The deterministic half of the convergence claim. Holding
		// subjectLockName from another goroutine and asserting the reconcile
		// waits pins "this path takes that lock" as a decision rather than as a
		// coincidence of timing -- and it is the lock that every other issuance
		// path for this subject takes, not one of its own.
		release := make(chan struct{})
		held := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			Expect(store.WithLock(ctx, subjectLockName(subject), func() error {
				close(held)
				<-release
				return nil
			})).To(Succeed())
		}()
		Eventually(held).Should(BeClosed())

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			close(done)
		}()

		Consistently(done, 200*time.Millisecond, 20*time.Millisecond).ShouldNot(BeClosed(),
			"the reconcile issued while another holder had the subject lock")
		close(release)
		Eventually(done).Should(BeClosed())
	})
})

// Four replicas racing to reconcile the same managed certificate.
//
// The pair of specs is the assertion. Convergence on its own would pass with
// the lock deleted whenever the scheduler happened to be kind, and a green run
// would prove nothing; the second spec establishes that this harness really can
// observe the failure, by removing the only thing that prevents it. Both drive
// the same store, the same barrier and the same delay, so the shared lock table
// is the single difference between them.
var _ = Describe("Four replicas reconciling one managed certificate", func() {
	const subject = "managed.test"

	var (
		ctx      context.Context
		storeDir string
		spec     CertSpec
		fake     *memStore
	)

	// replicaOn builds a CA over svc. Four of them over one StorageService
	// share its lock table, which is what a distributed backend gives replicas
	// on different hosts; four over separate services share nothing.
	replicaOn := func(svc *storage.StorageService) *CA {
		GinkgoHelper()
		c := New(svc, AutosignConfig{Mode: "off"}, "puppet.test")
		c.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		c.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(c.Init(ctx)).To(Succeed())
		return c
	}

	// serviceOverStore builds a StorageService whose backend declines same-host
	// locking, for the reason renewrace_test.go's noSameHostLocks gives: the
	// filesystem flock added by #187 would otherwise couple two services over
	// one directory, and these specs need to control that coupling rather than
	// inherit it.
	serviceOverStore := func() *storage.StorageService {
		backend := &noSameHostLocks{FilesystemBackend: storage.NewFilesystemBackend(storeDir)}
		return storage.NewWithBackend(backend, filepath.Join(storeDir, "private"))
	}

	// raceFourWays runs one reconcile pass on each replica, all released at
	// once, and returns how many issuances reached the store.
	raceFourWays := func(replicas []*CA) int {
		entry := ManagedCert{Spec: spec, Load: fake.load, Save: fake.save}
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, c := range replicas {
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				<-start
				// Errors are not asserted on: a replica that loses the race and
				// then finds the winner's certificate current returns no error,
				// but one whose lock acquisition times out legitimately does.
				// What this spec is about is how many certificates exist.
				_, _ = c.reconcileManagedCert(ctx, entry, time.Now().UTC())
			}()
		}
		close(start)
		wg.Wait()
		return fake.saveCount()
	}

	BeforeEach(func() {
		ctx = context.Background()
		storeDir = GinkgoT().TempDir()
		spec = CertSpec{
			Subject:     subject,
			DNSNames:    []string{subject},
			TTL:         90 * 24 * time.Hour,
			RenewBefore: 30 * 24 * time.Hour,
		}
		// Long enough that every replica is certainly inside Load before any of
		// them writes. It widens the window rather than deciding the outcome:
		// under a shared lock the losers simply wait their turn.
		fake = &memStore{delay: 10 * time.Millisecond}
	})

	It("converges on one certificate and one issuance", func() {
		svc := serviceOverStore()
		replicas := []*CA{replicaOn(svc), replicaOn(svc), replicaOn(svc), replicaOn(svc)}

		Expect(raceFourWays(replicas)).To(Equal(1),
			"the subject lock must serialise the four, so the three that follow the winner "+
				"load its certificate and find it current")

		serials, err := inventorySerialsFor(ctx, svc, subject)
		Expect(err).NotTo(HaveOccurred())
		Expect(serials).To(HaveLen(1), "one issuance means one inventory row")
		Expect(serials[0]).To(Equal(serialHexStr(fake.stored().SerialNumber)))
	})

	It("issues four times when the replicas share no lock", func() {
		// Not a property anybody wants -- it is what establishes that the spec
		// above is asserting something. Remove the lock from
		// reconcileManagedCert and the first spec becomes this one.
		replicas := []*CA{
			replicaOn(serviceOverStore()), replicaOn(serviceOverStore()),
			replicaOn(serviceOverStore()), replicaOn(serviceOverStore()),
		}

		Expect(raceFourWays(replicas)).To(BeNumerically(">", 1),
			"with nothing serialising them the four replicas must each issue; if this passes "+
				"with one issuance the harness cannot observe the failure the spec above rules out")
	})
})

// inventorySerialsFor returns the inventory serials recorded for subject, in
// the order they were written.
func inventorySerialsFor(ctx context.Context, svc *storage.StorageService, subject string) ([]string, error) {
	records, err := svc.InventoryEntries(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range records {
		if r.Subject == subject {
			out = append(out, r.Serial)
		}
	}
	return out, nil
}
