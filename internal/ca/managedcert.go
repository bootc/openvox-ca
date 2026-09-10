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

package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

// A managed certificate is a named leaf this CA keeps alive: it issues it,
// renews it on a loop, and supersedes the predecessor with a delay. It is
// described by three things -- a spec (what the certificate must be), a store
// (where the certificate and its key live), and the lock that serialises
// replicas working on it.
//
// The private key never reaches the backing store, and never reaches the local
// cadir either. It is generated inside the subject lock, handed to the store,
// and dropped. That is the invariant this mechanism exists to preserve: the
// backing store holds exactly one private key, the CA's own, and only under
// ca_key_provider: file. POST /generate still writes leaf keys to
// <cadir>/private/ and is unchanged by any of this.

// CertSpec describes what a managed certificate must be. It is fixed by
// configuration and never derived from anything a client submits, which is what
// makes reconcileManagedCert's place on the issuance seam defensible; see
// issuanceseam_test.go.
type CertSpec struct {
	// Subject is the certname. It becomes the certificate's Common Name, the
	// key it occupies in the inventory, and the subject recorded on the
	// pending-supersession list -- so it must be the same validated string
	// Revoke would be called with, or `revoke --certname` cannot find this
	// certificate's in-window predecessors.
	Subject string

	// DNSNames are the subjectAltName DNS entries the certificate must carry.
	// The Subject is not added automatically: a managed certificate's names are
	// configuration, and silently widening them is how a certificate ends up
	// answering to a name nobody asked it to.
	DNSNames []string

	// ExtKeyUsage is what the certificate may be used for. Nil means the
	// serverAuth+clientAuth pair every other issuance path uses.
	//
	// SECURITY: a serving certificate must be serverAuth-only. A clientAuth
	// certificate for a name that appears in puppet_server is a usable admin
	// credential, so a spec that wants one must say so rather than inherit it.
	// NIST 800-53: AC-6 (Least Privilege), CM-7 (Least Functionality)
	ExtKeyUsage []x509.ExtKeyUsage

	// TTL is the certificate lifetime. Zero means the CA's configured
	// LeafValidityDays, or the built-in default when that is unset. Whatever it
	// says, issueLeafLocked caps the result at the CA certificate's remaining
	// life -- which is the fact renewWindowFor exists to survive.
	TTL time.Duration

	// RenewBefore is how far ahead of expiry a replacement is issued. It must
	// be positive: a managed certificate whose window is zero is renewed only
	// once it has already expired, which is not a renewal loop.
	//
	// It is an upper bound on the window, not the window itself. See
	// renewWindowFor for what is actually applied and why the difference
	// matters.
	RenewBefore time.Duration
}

// Validate reports whether the spec can be issued from at all. Called for every
// entry before a reconcile pass touches storage, so a mistyped certname or an
// impossible window is refused as configuration rather than discovered as a
// certificate.
func (s CertSpec) Validate() error {
	if err := ValidateSubject(s.Subject); err != nil {
		return err
	}
	if err := validateDNSAltNames(s.DNSNames); err != nil {
		return err
	}
	if s.TTL < 0 {
		return fmt.Errorf("managed certificate %s: ttl must not be negative", s.Subject)
	}
	if s.RenewBefore <= 0 {
		return fmt.Errorf("managed certificate %s: renew_before must be positive, "+
			"or the certificate is only replaced after it has already expired", s.Subject)
	}
	return nil
}

// ManagedCert is one entry of the reconcile loop: a spec, plus the store that
// holds the material it describes.
//
// The store is two function fields rather than an interface, and that is a
// decision rather than an omission. The stores this mechanism serves differ in
// failure semantics and not merely in mechanism -- a serving store must be
// readable before the listener starts and its absence is fatal, whereas a
// component store's absence is routine and self-heals on the next pass. An
// interface spanning both would have to express that difference in its
// contract, which is a worse place for it than in the two callers. Each caller
// loads and saves its own way and asks the same question.
type ManagedCert struct {
	Spec CertSpec

	// Load reads the current material. An empty store is not an error: absent
	// material is an input to the decision, and reporting it as a failure would
	// stop the very pass that repairs it. A real read failure IS an error and
	// stops this entry for this pass -- reconciling against material we could
	// not read would reissue on every pass for as long as the store is down.
	Load func(ctx context.Context) (certPEM, keyPEM []byte, err error)

	// Save writes the certificate and its key together. It must be atomic with
	// respect to readers: a store holding one issuance's certificate and
	// another's key is well-formed and fails every handshake made against it.
	//
	// This is called inside the subject lock, which is why #189's EmitKey hook
	// is not used here. EmitKey fires before the lock is taken -- correct for a
	// single operator at a terminal, a race for a replicated loop, where two
	// replicas can each generate a key and each emit it before either takes the
	// lock.
	Save func(ctx context.Context, certPEM, keyPEM []byte) error
}

// issueReason says why a reconcile pass did or did not issue. Each value is a
// distinct diagnosis rather than a shade of the same one, because this is what
// an operator reads in the log when a certificate is being reissued more often
// than they expect.
type issueReason int

const (
	// reasonCurrent is the steady state: the stored material satisfies the
	// spec and is not yet inside its renew window.
	reasonCurrent issueReason = iota
	// reasonAbsent means the store holds no certificate. The first pass on a
	// fresh deployment, and the state after a store is deleted externally.
	reasonAbsent
	// reasonUnparseable means the store holds bytes that are not a certificate.
	reasonUnparseable
	// reasonKeyUnusable means the store holds a certificate but no key, or a
	// key that cannot be parsed. The "process died between signing and writing"
	// case lands here.
	reasonKeyUnusable
	// reasonKeyMismatch means the key parses but is not the certificate's.
	// Two replicas writing a pair non-atomically would produce this.
	reasonKeyMismatch
	// reasonNotOurs means the certificate was not issued by this CA. Reissuing
	// is right -- but note that nothing revokes the certificate being replaced
	// here, because its serial is not ours to put on our CRL.
	reasonNotOurs
	// reasonNamesMissing means the certificate does not carry every name the
	// spec requires, its Common Name included.
	reasonNamesMissing
	// reasonUsageMismatch means the certificate's extended key usages are not
	// the spec's.
	reasonUsageMismatch
	// reasonRevoked means the certificate is on the CRL.
	reasonRevoked
	// reasonRenewWindow means the certificate is inside its renew window --
	// which includes having expired outright.
	reasonRenewWindow
)

// String names the reason for a log line.
func (r issueReason) String() string {
	switch r {
	case reasonCurrent:
		return "current"
	case reasonAbsent:
		return "absent"
	case reasonUnparseable:
		return "unparseable"
	case reasonKeyUnusable:
		return "key-unusable"
	case reasonKeyMismatch:
		return "key-mismatch"
	case reasonNotOurs:
		return "not-issued-by-this-ca"
	case reasonNamesMissing:
		return "names-missing"
	case reasonUsageMismatch:
		return "usage-mismatch"
	case reasonRevoked:
		return "revoked"
	case reasonRenewWindow:
		return "renew-window"
	default:
		return fmt.Sprintf("issueReason(%d)", int(r))
	}
}

// renewWindowFor returns the renew-before window actually in force for leaf,
// which is not always the one the spec asks for.
//
// issueLeafLocked caps a leaf's validity at the CA certificate's *remaining*
// life. So a window that sits comfortably inside the configured lifetime grows
// larger than the certificate's real one as the CA certificate ages: with a
// 90-day ttl and a 30-day window, a CA certificate with 20 days left issues a
// 20-day leaf that is inside its window the moment it is signed. Every pass
// then reissues, for ever. That is the failure nine review rounds of the
// serving-certificate work closed, and it is why startup validation is not
// enough -- the configuration never changes, the CA certificate's remaining
// life does.
//
// The floor is half the certificate's own forward lifetime, derived from the
// certificate in hand rather than from configuration, so no setting can defeat
// it. It guarantees the loop makes progress: every issuance serves at least
// half the life it was actually granted before its successor is due. In an
// ordinary deployment it is invisible -- a 30-day window on a 90-day
// certificate is nowhere near the 45-day floor -- which is the property to
// want. It only binds when the alternative is a reissue loop.
//
// Forward lifetime, not NotAfter-NotBefore: issueLeafLocked backdates
// NotBefore by leafBackdate so a verifier with a slow clock still accepts a
// certificate we have just signed, and counting that backdate as life the
// certificate has to serve would reintroduce the same loop at short ttls (a
// one-hour certificate has a 25-hour span, and half of that is longer than the
// certificate lasts).
//
// This is only ever reached for certificates this CA issued: reasonNotOurs is
// decided first, so the leafBackdate assumption never has to hold for a
// foreign certificate.
func renewWindowFor(leaf *x509.Certificate, want CertSpec) time.Duration {
	forward := leaf.NotAfter.Sub(leaf.NotBefore) - leafBackdate
	if forward <= 0 {
		// A certificate with no forward life at all. Nothing to hold back;
		// letting the caller renew it immediately is the only useful answer.
		return 0
	}
	return min(want.RenewBefore, forward/2)
}

// issueDecision reports whether the material a store handed back satisfies
// want, and if not, why.
//
// Pure: no I/O, no locks, no clock of its own. Callers load their own material,
// establish revocation against whatever CRL they hold, and pass now in. That is
// the whole point of extracting it -- the alternative was a second copy of this
// reasoning for a second store, and the copies would diverge on exactly the
// kind of fix renewWindowFor is.
//
// certPEM and keyPEM are the raw bytes rather than parsed values so that
// "absent" and "unparseable" are decided here too. Splitting the parse out
// would put two of the reasons in the caller and the rest here, which is how a
// second caller comes to disagree about one of them.
//
// The parsed certificate is returned so the caller need not decode it again to
// reach the serial it must supersede. It is nil when there was nothing usable
// to parse.
func issueDecision(certPEM, keyPEM []byte, want CertSpec, issuer *x509.Certificate,
	now time.Time, revoked bool) (issue bool, reason issueReason, current *x509.Certificate) {
	if len(certPEM) == 0 {
		return true, reasonAbsent, nil
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return true, reasonUnparseable, nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, reasonUnparseable, nil
	}

	// Ownership before anything that reasons about how this certificate was
	// built. Every check below -- the renew window's leafBackdate arithmetic
	// most of all -- assumes we issued it, and a foreign certificate is
	// replaced whatever else is true of it. Note what the caller must not do
	// with the returned certificate on this arm: its serial is not ours and
	// must never reach our CRL.
	if issuer == nil {
		// An uninitialised CA cannot judge ownership, and answering "ours"
		// would be the unsafe direction. reconcileManagedCert refuses before
		// reaching here; this is the guard for a caller that does not.
		return true, reasonNotOurs, leaf
	}
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return true, reasonNotOurs, leaf
	}

	// The key, before the certificate's contents: a certificate whose key we do
	// not have is not a credential, however well it matches the spec.
	if len(keyPEM) == 0 {
		return true, reasonKeyUnusable, leaf
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return true, reasonKeyUnusable, leaf
	}
	key, err := parsePrivateKeyDER(keyBlock.Type, keyBlock.Bytes)
	if err != nil {
		return true, reasonKeyUnusable, leaf
	}
	if !publicKeysEqual(key.Public(), leaf.PublicKey) {
		return true, reasonKeyMismatch, leaf
	}

	if !leafCarriesNames(leaf, want) {
		return true, reasonNamesMissing, leaf
	}
	if !leafCarriesUsages(leaf, want) {
		return true, reasonUsageMismatch, leaf
	}

	// Revocation before the window: a revoked certificate is replaced now, not
	// when its window opens, and the caller wants to hear the more urgent of
	// the two reasons.
	if revoked {
		return true, reasonRevoked, leaf
	}

	if !now.Before(leaf.NotAfter.Add(-renewWindowFor(leaf, want))) {
		return true, reasonRenewWindow, leaf
	}
	return false, reasonCurrent, leaf
}

// publicKeysEqual reports whether two public keys are the same key.
//
// Every public key type crypto/x509 parses implements Equal; a type that does
// not is one this CA cannot reason about, and answering "equal" for it would
// mean accepting a certificate whose key we have not established we hold.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// leafCarriesNames reports whether leaf answers to every name want requires.
//
// Extra names are not a mismatch. A store's certificate may legitimately carry
// names an operator has since removed from the configuration, and reissuing to
// *narrow* a certificate on the next pass would drop names something may still
// be dialling, without the certificate having done anything wrong. Widening is
// what the spec asks for; narrowing waits for natural renewal.
func leafCarriesNames(leaf *x509.Certificate, want CertSpec) bool {
	if leaf.Subject.CommonName != want.Subject {
		return false
	}
	for _, name := range want.DNSNames {
		if !slices.Contains(leaf.DNSNames, name) {
			return false
		}
	}
	return true
}

// leafCarriesUsages reports whether leaf's extended key usages are exactly the
// ones want asks for.
//
// Exactly, not "at least": the spec's job here is to *withhold* clientAuth from
// a serving certificate, and a subset test would leave an existing
// serverAuth+clientAuth certificate satisfying a serverAuth-only spec until it
// expired of its own accord. That is the one drift where waiting is the wrong
// answer -- the certificate still in the store is a usable admin credential for
// a name in puppet_server, which is the whole reason the usage is configurable.
//
// The issue this implements did not list a usage mismatch among its reasons;
// it is here because without it a change to the setting has no effect until
// natural expiry, and the setting's only purpose is security.
func leafCarriesUsages(leaf *x509.Certificate, want CertSpec) bool {
	wanted := want.ExtKeyUsage
	if len(wanted) == 0 {
		wanted = defaultLeafExtKeyUsage()
	}
	got := slices.Clone(leaf.ExtKeyUsage)
	wanted = slices.Clone(wanted)
	slices.Sort(got)
	slices.Sort(wanted)
	return slices.Equal(got, slices.Compact(wanted))
}

// ReconcileManaged runs one pass over c.ManagedCerts, issuing whatever is due.
// It reports how many certificates it issued.
//
// One pass, not a loop: the timer belongs to the caller, which is what lets the
// server run it as an ordinary background job alongside the CRL refresher and
// the superseded sweep. Renewal is time-driven, so it cannot hang off
// CRLUpdated() the way the Kubernetes exporter does -- that channel can be
// silent for days on a quiet CA, and a certificate does not stop expiring
// because nothing was revoked.
//
// Entries are independent. One that fails is logged, counted as a failure, and
// left for the next pass; the rest still run. A single unreachable store must
// not stop every other managed certificate from renewing.
//
// Safe on every replica: each entry's work is serialised on that subject's
// cluster lock, and a replica that loses the race reads the certificate the
// winner just wrote and does nothing.
func (c *CA) ReconcileManaged(ctx context.Context) (int, error) {
	if len(c.ManagedCerts) == 0 {
		return 0, nil
	}

	issued := 0
	var firstErr error
	for _, m := range c.ManagedCerts {
		did, err := c.reconcileManagedCert(ctx, m, time.Now().UTC())
		if err != nil {
			slog.Warn("Managed certificate not reconciled",
				"subject", m.Spec.Subject, "error", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if did {
			issued++
		}
	}
	return issued, firstErr
}

// reconcileManagedCert runs one entry: load, decide, and issue if the decision
// says so, all inside that subject's cluster lock.
//
// Holding the lock across all three is what makes the mechanism converge. Two
// replicas reaching this at once do not both issue: the loser blocks, and its
// load then returns the certificate the winner just wrote, which the decision
// finds current. Splitting the lock so that only the issuance were inside it
// would leave both replicas deciding against the same stale material and both
// issuing -- one certificate wasted per replica per pass, each superseding the
// last.
//
// Lock ordering: subject-lock (distributed) -> c.mu for the issuance, and
// subject-lock -> crl -> c.mu for the supersession, both of which are the
// orders every other issuance path already takes. The lock is derived from the
// subject rather than configured: the serving certificate's dedicated lock on
// the closed #165 existed because replicas shared one blob and were allowed to
// disagree about their own hostname, and neither premise survives a managed
// certificate having a configured name and a store of its own.
//
// The caller must NOT hold c.mu.
func (c *CA) reconcileManagedCert(ctx context.Context, m ManagedCert, now time.Time) (bool, error) {
	if err := m.Spec.Validate(); err != nil {
		return false, err
	}
	if m.Load == nil || m.Save == nil {
		return false, fmt.Errorf("managed certificate %s: store is not configured", m.Spec.Subject)
	}

	c.mu.RLock()
	issuer, initialised := c.CACert, c.CACert != nil && c.CAKey != nil
	c.mu.RUnlock()
	if !initialised {
		return false, ErrNotInitialized
	}

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()

	subject := m.Spec.Subject
	issued := false
	err := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		certPEM, keyPEM, err := m.Load(ctx)
		if err != nil {
			return fmt.Errorf("reading the stored material for %s: %w", subject, err)
		}

		// Revocation is an input to the decision but needs a serial, and the
		// serial needs a parse the decision is about to do anyway. Parsing
		// twice is the cost of keeping issueDecision pure, and it is a parse of
		// bytes already in memory. A certificate that will not parse here is
		// one issueDecision reports as unparseable a moment later, so treating
		// the failure as "not revoked" decides nothing.
		revoked := c.storedMaterialRevoked(ctx, certPEM, subject)

		issue, reason, current := issueDecision(certPEM, keyPEM, m.Spec, issuer, now, revoked)
		if !issue {
			slog.Debug("Managed certificate is current",
				"subject", subject, "not_after", current.NotAfter.Format(time.RFC3339))
			return nil
		}
		slog.Info("Issuing managed certificate", "subject", subject, "reason", reason.String())

		did, err := c.issueManagedLocked(ctx, m, reason, current)
		issued = did
		return err
	})
	if err != nil {
		return false, err
	}
	return issued, nil
}

// storedMaterialRevoked reports whether the certificate in certPEM is on this
// CA's CRL.
//
// Fails toward "not revoked", which is the safe direction *here* and only here:
// the answer is used to decide whether to replace a certificate, and a false
// negative costs one deferred reissue that the renew window will make anyway,
// while a false positive would reissue on every pass for as long as the CRL is
// unreadable. This is not an authentication decision and must not be reused as
// one -- refuseIfRevoked, which is, fails closed.
func (c *CA) storedMaterialRevoked(ctx context.Context, certPEM []byte, subject string) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	revoked, err := c.IsRevokedSerial(ctx, leaf.SerialNumber)
	if err != nil {
		slog.Warn("Could not check the stored managed certificate against the CRL; "+
			"treating it as not revoked for this pass",
			"subject", subject, "error", err)
		return false
	}
	return revoked
}

// issueManagedLocked generates a key, signs a certificate for m's spec, writes
// the pair to m's store, and retires the predecessor. The caller must hold
// subject's lock and must NOT hold c.mu.
//
// The key is generated here and dropped when this returns. It is written to m's
// store and to nowhere else: not to the backing store, and not to the local
// cadir either. That is why RetainPrivateKeyInStorage has no equivalent on this
// path -- there is nothing to opt out of.
func (c *CA) issueManagedLocked(ctx context.Context, m ManagedCert, reason issueReason,
	current *x509.Certificate) (bool, error) {
	subject := m.Spec.Subject

	leafCfg := c.LeafKeyConfig
	if leafCfg.Algo == "" {
		leafCfg = DefaultLeafKeyConfig
	}
	// CPU-bound and touching no shared state, so outside c.mu -- but inside the
	// subject lock, unlike GenerateWithOptions, because the key must not exist
	// before this replica has established that it is the one issuing.
	key, err := generateKey(leafCfg)
	if err != nil {
		return false, fmt.Errorf("generating a key for %s: %w", subject, err)
	}
	keyPEM, err := marshalPrivateKeyPEM(key)
	if err != nil {
		return false, fmt.Errorf("marshalling the key for %s: %w", subject, err)
	}

	certPEM, err := func() ([]byte, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.issueLeafLocked(ctx, subject,
			pkix.Name{CommonName: subject}, key.Public(),
			subjectAltNames{DNSNames: m.Spec.DNSNames}, nil,
			m.Spec.ExtKeyUsage, m.Spec.TTL)
	}()
	if err != nil {
		return false, fmt.Errorf("signing a certificate for %s: %w", subject, err)
	}

	// The serial of what we just signed, for the rollback below. Read from the
	// PEM rather than plumbed out of issueLeafLocked so the rollback revokes
	// the bytes that were actually produced.
	newSerial, err := certSerialFromPEM(certPEM)
	if err != nil {
		// Unreachable for bytes issueLeafLocked just signed, and there is
		// nothing useful to do about it: the certificate exists either way.
		slog.Warn("Could not read the serial of a just-issued managed certificate; "+
			"a store write failure will not be able to revoke it",
			"subject", subject, "error", err)
	}

	if err := m.Save(ctx, certPEM, keyPEM); err != nil {
		// Nothing ever saw this key: it was generated in this call, under this
		// lock, and the store refused it. So the certificate is revoked
		// immediately rather than superseded with a delay -- a window exists to
		// let relying parties pick up a replacement, and there are none. The
		// predecessor is left exactly as it was, still valid and still in the
		// store, and the next pass retries.
		if newSerial != "" {
			if rerr := c.Storage.WithLock(ctx, lockNameCRL, func() error {
				c.mu.Lock()
				defer c.mu.Unlock()
				return c.revokeSerialLocked(ctx, newSerial)
			}); rerr != nil {
				// Counted by revokeSerialLocked and signCRLLocked where it
				// reached them. Say plainly what is left behind: a live
				// certificate whose key is gone, which nothing else will
				// retire before it expires.
				slog.Error("A managed certificate could not be stored and could not then be revoked; "+
					"it is live until it expires",
					"subject", subject, "serial", newSerial, "error", rerr)
			}
		}
		return false, fmt.Errorf("writing the material for %s to its store: %w", subject, err)
	}

	// Retire the predecessor, now that its replacement is signed AND stored.
	//
	// Only when we have one that is ours and not already revoked. A foreign
	// certificate's serial must never reach our CRL -- it identifies a
	// different certificate under a different issuer -- and an already-revoked
	// one needs nothing further. Best effort in every case: the replacement is
	// written and a failure here must not undo it.
	if current != nil && reason != reasonNotOurs && reason != reasonRevoked {
		oldSerial := serialHexStr(current.SerialNumber)
		if err := c.supersedeReplaced(ctx, subject, oldSerial); err != nil {
			// Counted already -- crlUpdateFailures on the immediate path,
			// supersedeFailures on the delayed one.
			slog.Warn("Managed certificate issued, but its predecessor was not retired",
				"subject", subject, "serial", oldSerial, "error", err)
		}
	}
	return true, nil
}

// certSerialFromPEM returns the canonical serial of the first certificate in
// certPEM, in the same form serialHexStr produces everywhere else -- which is
// what revokeSerialLocked and the pending-supersession list both compare
// against.
func certSerialFromPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return serialHexStr(cert.SerialNumber), nil
}
