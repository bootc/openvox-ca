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

package main

import (
	"context"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

var _ = Describe("The managed-certificate reconcile job", func() {
	// A store that records what the loop asked of it. Nothing here is about
	// what a real store does -- these specs are about the loop.
	var (
		mu    sync.Mutex
		loads int
	)

	managed := func(subject string) ca.ManagedCert {
		return ca.ManagedCert{
			Spec: ca.CertSpec{
				Subject:     subject,
				DNSNames:    []string{subject},
				TTL:         90 * 24 * time.Hour,
				RenewBefore: 30 * 24 * time.Hour,
			},
			Load: func(context.Context) ([]byte, []byte, error) {
				mu.Lock()
				defer mu.Unlock()
				loads++
				return nil, nil, nil
			},
			// Refuse the write, so a spec that only means to count passes does
			// not accumulate certificates it never asserts on.
			Save: func(context.Context, []byte, []byte) error {
				return context.Canceled
			},
		}
	}

	BeforeEach(func() {
		mu.Lock()
		loads = 0
		mu.Unlock()
	})

	It("is not started when no managed certificates are configured", func() {
		// The mechanism is dormant by default: a CA that configures none runs
		// exactly as it did before, with no extra goroutine.
		Expect(jobNames(&serverConfig{})).NotTo(ContainElement(jobManagedCerts))
	})

	It("is started when there is something to keep alive", func() {
		c, _ := newRefresherTestCA()
		c.ManagedCerts = []ca.ManagedCert{managed("managed.test")}

		var names []string
		for _, job := range backgroundJobs(&serverConfig{}, c) {
			names = append(names, job.name)
		}
		Expect(names).To(ContainElement(jobManagedCerts))
	})

	It("reconciles once at startup, before the first tick", func() {
		// On a fresh deployment nothing is in the store yet, and waiting a full
		// interval to issue would mean waiting an interval for whatever depends
		// on that certificate.
		c, _ := newRefresherTestCA()
		c.ManagedCerts = []ca.ManagedCert{managed("managed.test")}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			// An interval far longer than this spec lives, so a pass can only
			// be the startup one.
			runManagedCertReconciler(ctx, c, time.Hour)
		}()

		Eventually(func() int {
			mu.Lock()
			defer mu.Unlock()
			return loads
		}).Should(Equal(1))

		cancel()
		Eventually(done).Should(BeClosed())
	})

	It("keeps reconciling on the timer", func() {
		c, _ := newRefresherTestCA()
		c.ManagedCerts = []ca.ManagedCert{managed("managed.test")}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			runManagedCertReconciler(ctx, c, 10*time.Millisecond)
		}()

		// More than one pass is the whole claim: renewal is time-driven, so
		// this loop must not be a one-shot at startup.
		Eventually(func() int {
			mu.Lock()
			defer mu.Unlock()
			return loads
		}).Should(BeNumerically(">", 2))

		cancel()
		Eventually(done).Should(BeClosed())
	})

	It("keeps going when an entry fails", func() {
		// Entries are independent: one unreachable store must not stop every
		// other managed certificate from renewing, and must not stop the loop.
		c, _ := newRefresherTestCA()
		failing := managed("broken.test")
		failing.Load = func(context.Context) ([]byte, []byte, error) {
			return nil, nil, context.DeadlineExceeded
		}
		c.ManagedCerts = []ca.ManagedCert{failing, managed("managed.test")}

		issued, err := c.ReconcileManaged(context.Background())
		Expect(err).To(HaveOccurred(), "the failure must be reported, not swallowed")
		Expect(issued).To(BeZero())

		mu.Lock()
		defer mu.Unlock()
		Expect(loads).To(Equal(1),
			"the entry after the failing one must still have been attempted")
	})
})
