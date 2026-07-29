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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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

	return ImportCAMaterial(ctx, store, certBundlePEM, keyPEM, crlPEM, caKey)
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
// with signer.
func ImportCAMaterial(ctx context.Context, store *storage.StorageService, certBundlePEM, keyPEM, crlPEM []byte, signer crypto.Signer) error {
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
	// Without this the CA could be left in a state where it holds a certificate
	// it cannot sign under: every issuance would fail, and every certificate
	// already issued under the previous key would stop verifying. This is the
	// single check that makes importing a certificate without its private key
	// safe, so it is deliberately algorithm-agnostic (compare marshalled
	// SubjectPublicKeyInfo) rather than type-switching.
	// NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
	certPubDER, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal cert public key: %w", err)
	}
	keyPubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("failed to marshal signing key's public component: %w", err)
	}
	if !bytes.Equal(certPubDER, keyPubDER) {
		return fmt.Errorf("the CA key does not match the certificate's public key: refusing to import a "+
			"certificate this CA could not sign under (certificate subject %q)", caCert.Subject.CommonName)
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
	if err := store.SaveCACert(ctx, certBundlePEM); err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}

	// --- Write CA public key ---
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err == nil {
		pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
		_ = store.SaveCAPubKey(ctx, pubKeyPEM)
	}

	// --- Handle CRL ---
	if crlPEM != nil {
		// Validate every block, not just the first: a CRL chain supplied here is
		// served verbatim to agents, so an unparseable block further down would
		// surface as a broken CRL on every node rather than an import error.
		rest := crlPEM
		blocks := 0
		for {
			var crlBlock *pem.Block
			crlBlock, rest = pem.Decode(rest)
			if crlBlock == nil {
				break
			}
			if crlBlock.Type != "X509 CRL" {
				continue
			}
			if _, err := x509.ParseRevocationList(crlBlock.Bytes); err != nil {
				return fmt.Errorf("failed to parse CRL %d in crl-chain: %w", blocks+1, err)
			}
			blocks++
		}
		if blocks == 0 {
			return fmt.Errorf("crl-chain does not contain a valid X509 CRL PEM block")
		}
		// Import-time write: runs before any CRL consumer exists, so it
		// deliberately skips the crlNotify signal (see signCRLLocked).
		if err := store.UpdateCRL(ctx, crlPEM); err != nil {
			return fmt.Errorf("failed to write CRL: %w", err)
		}
	} else {
		// Generate a fresh empty CRL.
		now := time.Now().UTC()
		crlTemplate := &x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: now,
			NextUpdate: now.Add(CRLValidity),
		}
		crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, signer)
		if err != nil {
			return fmt.Errorf("failed to create initial CRL: %w", err)
		}
		generatedCRL := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
		// Import-time write: runs before any CRL consumer exists, so it
		// deliberately skips the crlNotify signal (see signCRLLocked).
		if err := store.UpdateCRL(ctx, generatedCRL); err != nil {
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
