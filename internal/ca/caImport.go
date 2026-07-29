// Copyright (C) 2026 Trevor Vaughan
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
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// ImportCA imports an external CA cert/key into a storage directory.
// It validates the cert/key pair, writes the files, and initialises
// the serial and inventory files when they are absent.
//
// Supported key formats: RSA PKCS1 ("RSA PRIVATE KEY"), EC SEC1
// ("EC PRIVATE KEY"), and PKCS8 ("PRIVATE KEY") for both RSA and ECDSA.
//
// crlPEM may be nil; when nil a fresh empty CRL is generated and written.
//
// This is a thin wrapper over ImportCAMaterial for the case where the CA's
// private key is a local PEM blob. When the key lives at a provider (an OpenBao
// Transit key, a PKCS#11 token) there is no blob to pass and callers use
// ImportCAMaterial directly with a crypto.Signer.
//
// This is an offline operation; no CA daemon is required.
func ImportCA(ctx context.Context, store *storage.StorageService, certBundlePEM, keyPEM, crlPEM []byte) error {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("private-key does not contain a valid PEM block")
	}
	caKey, err := parsePrivateKeyDER(keyBlock.Type, keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return ImportCAMaterial(ctx, store, certBundlePEM, keyPEM, crlPEM, caKey, CRLValidity)
}

// ErrCACertExists reports that storage already holds a CA certificate and the
// caller did not ask to replace it.
var ErrCACertExists = errors.New("a CA certificate already exists")

// ErrCACertWrite wraps a failure to write the CA certificate blob, so callers
// can tell it apart from the validation and CRL failures that surround it.
// Guidance about read-only mounts is only ever right for this one.
var ErrCACertWrite = errors.New("writing the CA certificate")

// ImportCACertificate installs a CA certificate chain signed by an external
// parent, for a CA whose private key is held elsewhere — a Transit key, a
// PKCS#11 token, or a local blob this function never touches.
//
// signer proves the certificate binds this CA's key. When storage already holds
// a certificate the import is refused unless force is set, in which case the
// stored CRL is re-signed under the incoming certificate so it stays verifiable.
//
// The whole sequence runs under the bootstrap lock. Replacing a live CA
// certificate is a read-modify-write spanning the certificate and the CRL, and
// the documented procedure restarts replicas *after* the import — so replicas
// are serving throughout. Without the lock a revocation landing mid-import
// either overwrites the re-signed CRL with one nothing can verify, or is itself
// lost. Reporting whether a certificate was replaced lets the caller name the
// restart that must follow.
func ImportCACertificate(ctx context.Context, store *storage.StorageService, certBundlePEM []byte, signer crypto.Signer, crlValidity time.Duration, force bool) (replaced bool, err error) {
	certs, err := ParseCABundle(certBundlePEM)
	if err != nil {
		return false, fmt.Errorf("cert-bundle: %w", err)
	}
	if err := ValidateCABundleOrder(certs); err != nil {
		return false, fmt.Errorf("cert-bundle: %w", err)
	}
	if err := AssertSignerMatchesCert(certs[0], signer); err != nil {
		return false, err
	}

	lockCtx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	err = store.WithLock(lockCtx, lockNameBootstrap, func() error {
		hasCert, err := store.HasCACert(ctx)
		if err != nil {
			return fmt.Errorf("checking for an existing CA certificate: %w", err)
		}
		if hasCert && !force {
			return fmt.Errorf("%w: refusing to replace it, because every certificate issued under the "+
				"current one stops verifying if the replacement does not chain to it. Pass --force if "+
				"that is intended", ErrCACertExists)
		}
		replaced = hasCert

		// The stored CRL was signed by the key being replaced and names the
		// subject being replaced; whether this import is a re-key, a re-subject
		// or both, nothing can verify it afterwards. Revocation entries are
		// carried across.
		var crlPEM []byte
		if hasCert {
			crlPEM, err = ResignStoredCRL(ctx, store, certs[0], signer, crlValidity)
			if err != nil {
				return err
			}
		}
		return ImportCAMaterial(ctx, store, certBundlePEM, nil, crlPEM, signer, crlValidity)
	})
	if err != nil {
		return false, err
	}
	return replaced, nil
}

// ImportCAMaterial writes an externally-issued CA certificate bundle and its
// CRL into storage, after proving that signer holds the private key the leading
// certificate binds.
//
// signer is the proof, not the payload: it establishes that this CA will be
// able to sign under the certificate being imported. keyPEM is the payload and
// may be nil — when the key lives at a provider there is no blob to persist,
// and passing nil skips the key write entirely while leaving every other check
// in place. Callers holding a local key pass both; the two are redundant by
// construction in that case, and deliberately so, because the roles differ.
//
// crlPEM may be nil, in which case a fresh empty CRL is generated and signed
// with signer, valid for crlValidity.
func ImportCAMaterial(ctx context.Context, store *storage.StorageService, certBundlePEM, keyPEM, crlPEM []byte, signer crypto.Signer, crlValidity time.Duration) error {
	// --- Parse and validate the certificate bundle ---
	certs, err := ParseCABundle(certBundlePEM)
	if err != nil {
		return fmt.Errorf("cert-bundle: %w", err)
	}
	if err := ValidateCABundleOrder(certs); err != nil {
		return fmt.Errorf("cert-bundle: %w", err)
	}
	caCert := certs[0]

	// --- SECURITY: prove the signer holds the key this certificate binds ---
	if err := AssertSignerMatchesCert(caCert, signer); err != nil {
		return err
	}

	// --- Ensure directories exist ---
	if err := store.EnsureDirs(ctx); err != nil {
		return fmt.Errorf("failed to create CA directories: %w", err)
	}

	// --- Write CA key, when there is one to write ---
	if keyPEM != nil {
		if err := store.SaveCAKey(ctx, keyPEM); err != nil {
			return fmt.Errorf("failed to write CA key: %w", err)
		}
	}

	// --- Write CA cert (the whole bundle, root last) ---
	// Re-encoded from the parsed chain rather than passed through, so what is
	// stored and served is exactly what was validated. The DER is unchanged.
	if err := store.SaveCACert(ctx, EncodeCABundle(certs)); err != nil {
		return fmt.Errorf("%w: %w", ErrCACertWrite, err)
	}

	// --- Write CA public key ---
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("failed to marshal signing key's public component: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	if err := store.SaveCAPubKey(ctx, pubKeyPEM); err != nil {
		return fmt.Errorf("failed to write CA public key: %w", err)
	}

	// --- Handle CRL ---
	if crlPEM != nil {
		// Every block must parse. The blob is served verbatim to every agent,
		// and Puppet's default certificate_revocation = chain makes an agent
		// parse all of it, so an unparseable block further down would surface
		// as a broken CRL across the fleet rather than as an import error here.
		incoming, err := decodeCRLChain(crlPEM)
		if err != nil {
			return fmt.Errorf("crl-chain: %w", err)
		}
		if len(incoming) == 0 {
			return fmt.Errorf("crl-chain does not contain a valid X509 CRL PEM block")
		}

		// Every reader takes block 0 as this CA's own CRL, so put it there.
		// An operator assembling a chain by hand has no reason to know that,
		// and correcting it once at import is better than misreading it on
		// every subsequent load.
		ordered, foundOurs := orderCRLChain(incoming, caCert)
		if !foundOurs {
			// A chain of purely upstream CRLs is legitimate — an operator may
			// supply ancestors and expect this CA to issue its own. It is also
			// how someone refreshes ancestor CRLs with the tools available
			// today, on a CA that has been issuing for months.
			//
			// So prefer a CRL of ours already in storage over a fresh empty
			// one. Leading with an empty CRL would leave every reader taking
			// block 0 and concluding nothing is revoked, which looks entirely
			// healthy and silently un-revokes the fleet.
			ourCRL := storedOwnCRL(ctx, store, caCert)
			if ourCRL == nil {
				ourCRL, err = generateEmptyCRL(caCert, signer, crlValidity)
				if err != nil {
					return err
				}
			}
			ordered = append([]*x509.RevocationList{ourCRL}, ordered...)
		}

		// Re-encoded from the parsed chain rather than passed through, so what
		// is stored and served is exactly what was validated — on both branches,
		// not just the reordered one.
		//
		// Import-time write: runs before any CRL consumer exists, so it
		// deliberately skips the crlNotify signal (see signCRLLocked).
		if err := store.UpdateCRL(ctx, encodeCRLChain(ordered)); err != nil {
			return fmt.Errorf("failed to write CRL: %w", err)
		}
	} else {
		generatedCRL, err := generateEmptyCRL(caCert, signer, crlValidity)
		if err != nil {
			return err
		}
		// Import-time write: runs before any CRL consumer exists, so it
		// deliberately skips the crlNotify signal (see signCRLLocked).
		if err := store.UpdateCRL(ctx, encodeCRLChain([]*x509.RevocationList{generatedCRL})); err != nil {
			return fmt.Errorf("failed to write CRL: %w", err)
		}
	}

	// --- Initialise serial if absent ---
	hasSerial, err := store.HasSerial(ctx)
	if err != nil {
		return fmt.Errorf("checking serial: %w", err)
	}
	if !hasSerial {
		if err := store.WriteSerial(ctx, "0001"); err != nil {
			return fmt.Errorf("failed to write serial: %w", err)
		}
	}

	// --- Initialise inventory if absent ---
	if err := store.TouchInventory(ctx); err != nil {
		return fmt.Errorf("failed to create inventory: %w", err)
	}

	return nil
}

// storedOwnCRL returns the CRL in storage that cert signed, or nil when there
// is none — including when storage cannot be read or holds nothing usable,
// since every caller's fallback is to generate a fresh one.
func storedOwnCRL(ctx context.Context, store *storage.StorageService, cert *x509.Certificate) *x509.RevocationList {
	existing, err := store.GetCRL(ctx)
	if err != nil {
		return nil
	}
	stored, err := decodeCRLChain(existing)
	if err != nil {
		return nil
	}
	for _, crl := range stored {
		if crlSignedBy(cert, crl) {
			return crl
		}
	}
	return nil
}

// generateEmptyCRL signs a fresh, empty CRL for cert.
//
// Number 1 is correct here and only here: this runs when the imported chain
// carries no CRL of ours, so there is no previous number of ours to advance
// from. Re-signing an existing CRL goes through signCRLLocked, which bumps.
func generateEmptyCRL(cert *x509.Certificate, key crypto.Signer, validity time.Duration) (*x509.RevocationList, error) {
	now := time.Now().UTC()
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(validity),
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, cert, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create initial CRL: %w", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the generated CRL: %w", err)
	}
	return crl, nil
}
