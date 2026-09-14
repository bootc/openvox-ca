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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// caOnDisk returns the CA certificate the cadir actually holds, and the raw
// PEM it was read from.
//
// Deliberately a second, independent route to the subject: the specs below
// compare setup's output against this, and if the expected value were
// assembled from --hostname the same way the code under test assembles it, no
// assertion over the pair could fail whatever setup printed.
func caOnDisk(caDir string) (*x509.Certificate, []byte) {
	GinkgoHelper()
	pemBytes, err := os.ReadFile(filepath.Join(caDir, "ca_crt.pem"))
	Expect(err).NotTo(HaveOccurred(), "reading the CA certificate")
	block, _ := pem.Decode(pemBytes)
	Expect(block).NotTo(BeNil(), "the CA certificate must be PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred(), "parsing the CA certificate")
	return cert, pemBytes
}

// seedExistingCA bootstraps a real CA into caDir under a subject of its own,
// unrelated to any --hostname a spec then passes to setup.
//
// ECDSA P-256 rather than the shipped RSA 4096 default: this fixture exists
// only to make setup's load path reachable, and the key algorithm has no
// bearing on which subject setup reports. The one spec that must exercise the
// bootstrap path drives setup itself, defaults and all.
func seedExistingCA(caDir, hostname string) {
	GinkgoHelper()
	seeded := ca.New(storage.New(caDir), ca.AutosignConfig{Mode: "off"}, hostname)
	seeded.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	Expect(seeded.Init(context.Background())).To(Succeed(), "seeding an existing CA")
}

// `setup` calls CA.Init, which either bootstraps a new CA or loads one that is
// already there, and then reports success. It used to assemble that report out
// of the --hostname flag on both paths, so pointing setup at a cadir that
// already held a CA printed "CA initialized" and a CN that existed nowhere:
// the truthful line ("Loaded existing CA") went to stderr as a log record and
// the false one to stdout, so the ordinary capture kept the wrong one.
//
// Two separate claims were wrong, and these specs pin both: the value, which
// must come off the certificate rather than the flag, and the verb, which must
// not assert an initialisation that did not happen.
var _ = Describe("setup subcommand output", func() {
	It("names the subject of the CA it has just created", func() {
		// The bootstrap path, and the control for the load-path specs below:
		// here the CN genuinely is derived from --hostname, so a fix that
		// simply stopped printing anything useful would fail this.
		caDir := GinkgoT().TempDir()

		out, err := captureStdout([]string{
			"setup", "--cadir", caDir, "--hostname", "bootstrapped.example.com",
		})
		Expect(err).NotTo(HaveOccurred(), "setup")

		cert, _ := caOnDisk(caDir)
		// The "Puppet CA: " prefix is minted into the subject and is Puppet
		// compatibility surface. Asserted here so that reporting the real
		// subject cannot quietly become an opportunity to restyle it.
		Expect(cert.Subject.CommonName).To(Equal("Puppet CA: bootstrapped.example.com"))
		Expect(out).To(ContainSubstring(cert.Subject.CommonName))
		Expect(out).To(ContainSubstring(caDir))
	})

	Context("against a cadir that already holds a CA", func() {
		const (
			seededHost = "already-here.example.com"
			flagHost   = "totally-different.example.com"
		)

		var (
			caDir  string
			before []byte
			out    string
		)

		BeforeEach(func() {
			caDir = GinkgoT().TempDir()
			seedExistingCA(caDir, seededHost)
			_, before = caOnDisk(caDir)

			var err error
			out, err = captureStdout([]string{
				"setup", "--cadir", caDir, "--hostname", flagHost,
			})
			Expect(err).NotTo(HaveOccurred(), "setup over an existing CA")
		})

		It("reports the subject it loaded, not the --hostname it was passed", func() {
			cert, _ := caOnDisk(caDir)

			Expect(out).To(ContainSubstring(cert.Subject.CommonName),
				"the CN printed must be the one on the certificate:\n%s", out)
			Expect(out).NotTo(ContainSubstring(flagHost),
				"--hostname has no effect on the load path, so echoing it names a CA that exists nowhere:\n%s", out)
		})

		It("does not claim to have initialised a CA it only loaded", func() {
			Expect(out).NotTo(ContainSubstring("CA initialized"),
				"nothing was initialised:\n%s", out)
			Expect(out).To(ContainSubstring("Existing CA found"),
				"the load path must say what actually happened:\n%s", out)
		})

		It("leaves the existing CA untouched", func() {
			// The other way to make the message true would be to re-bootstrap
			// so the CN matches the flag, which would retire the CA and
			// invalidate every certificate issued under it. Pin the certificate
			// bytes so a fix cannot take that route.
			_, after := caOnDisk(caDir)
			Expect(after).To(Equal(before), "setup must not replace an existing CA")
		})
	})

	It("quotes a subject read off disk so it cannot forge a line", func() {
		// On the load path the printed value comes from a certificate that was
		// found in the cadir rather than from anything this process chose, so
		// AGENTS.md's escaping rule applies to it: an unescaped control
		// character in the subject would let the certificate write its own
		// line of operator-facing output.
		const forged = "evil\nCA initialized in /somewhere-else"
		caDir := GinkgoT().TempDir()
		seedExistingCA(caDir, forged)

		cert, _ := caOnDisk(caDir)
		Expect(cert.Subject.CommonName).To(ContainSubstring("\n"),
			"the fixture must actually carry the control character, or this spec asserts nothing")

		out, err := captureStdout([]string{
			"setup", "--cadir", caDir, "--hostname", "unused.example.com",
		})
		Expect(err).NotTo(HaveOccurred(), "setup over an existing CA")

		Expect(out).To(ContainSubstring(strconv.Quote(cert.Subject.CommonName)),
			"the subject must appear, escaped:\n%s", out)
		Expect(out).NotTo(ContainSubstring("\nCA initialized"),
			"a newline in the subject must not start a line of its own:\n%s", out)
	})
})
