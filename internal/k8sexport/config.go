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

// Package k8sexport publishes the CA certificate and/or CRL into Kubernetes
// Secrets and ConfigMaps. It is an optional feature: when no targets are
// configured nothing in this package runs. Objects are reconciled with
// server-side apply so each export is an idempotent create-or-update.
//
// The exporter authenticates with the pod's in-cluster ServiceAccount, so it is
// only available when openvox-ca itself runs inside a Kubernetes cluster.
package k8sexport

import (
	"fmt"
	"strings"
)

// Kind enumerates the Kubernetes object kinds an export target may be. The
// canonical spellings match Kubernetes; configuration accepts any case and is
// normalised to these values.
const (
	KindSecret    = "Secret"
	KindConfigMap = "ConfigMap"
)

const (
	// defaultFieldManager is the server-side apply field manager used when the
	// operator does not set one. It scopes ownership of the fields this exporter
	// writes so other managers (e.g. kubectl) can co-own unrelated fields.
	defaultFieldManager = "openvox-ca"
	// defaultCertKey / defaultCRLKey are the data keys used when a target does
	// not override them. They follow common Kubernetes trust-bundle conventions.
	defaultCertKey = "ca.crt"
	defaultCRLKey  = "ca.crl"
	// defaultServingCertKey / defaultServingKeyKey follow the kubernetes.io/tls
	// convention instead, because that is what an Ingress or Gateway reading
	// the Secret expects to find.
	defaultServingCertKey = "tls.crt"
	defaultServingKeyKey  = "tls.key"
)

// Export scopes select how much of a chain a target publishes.
const (
	// ScopeSelf publishes only this CA's own certificate or CRL — block 0 of
	// the stored bundle. The default, and identical to ScopeChain on a CA that
	// issues its own root.
	ScopeSelf = "self"
	// ScopeChain publishes the stored bundle or CRL chain verbatim.
	ScopeChain = "chain"
	// ScopeRoot publishes the last certificate in the bundle: the trust anchor
	// rather than the issuing CA. Certificates only — a CRL chain has no
	// equivalent, since the root's CRL is simply one of its members.
	ScopeRoot = "root"
)

// Config is the top-level kubernetes_export configuration block. The feature is
// considered enabled when Targets is non-empty.
type Config struct {
	// FieldManager is the server-side apply field manager name. Empty selects
	// defaultFieldManager.
	FieldManager string `yaml:"field_manager"`
	// Targets is the set of Secrets/ConfigMaps to maintain.
	Targets []Target `yaml:"targets"`
}

// Metadata mirrors the shape of a Kubernetes object's metadata block, so a
// target reads like the manifest it produces.
type Metadata struct {
	// Name is the object's metadata.name (required).
	Name string `yaml:"name"`
	// Namespace is the object's namespace. Empty resolves at runtime to the
	// pod's own ServiceAccount namespace.
	Namespace string `yaml:"namespace"`
	// Labels and Annotations are applied to the object's metadata.
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

// Target describes a single Secret or ConfigMap to maintain.
type Target struct {
	// Kind is "Secret" or "ConfigMap" (case-insensitive; normalised by
	// Validate to the canonical Kubernetes spelling).
	Kind string `yaml:"kind"`
	// Metadata carries the object's name, namespace, labels and annotations.
	Metadata Metadata `yaml:"metadata"`
	// Type sets a Secret's type field (e.g. "Opaque"). Only valid for Secrets.
	// When empty the exporter does not manage the type field at all, so it can
	// co-maintain a Secret whose type is owned by another manager (e.g. a
	// kubernetes.io/tls Secret created by Flux): the API server defaults a new
	// Secret to Opaque, and an existing Secret's type is left untouched.
	Type string `yaml:"type"`
	// Cert and CRL select which materials to include. At least one of the four
	// material flags must be true.
	Cert bool `yaml:"cert"`
	CRL  bool `yaml:"crl"`
	// ServingCert and ServingKey publish the self-provisioned serving
	// certificate and its private key, for an Ingress or Gateway that
	// terminates TLS in front of the CA. Only meaningful with
	// tls_self_provision enabled.
	ServingCert bool `yaml:"serving_cert"`
	ServingKey  bool `yaml:"serving_key"`
	// CertKey and CRLKey name the data entries for the cert and CRL. Empty
	// selects defaultCertKey / defaultCRLKey.
	CertKey string `yaml:"cert_key"`
	CRLKey  string `yaml:"crl_key"`
	// ServingCertKey and ServingKeyKey name the data entries for the serving
	// material. Empty selects defaultServingCertKey / defaultServingKeyKey.
	ServingCertKey string `yaml:"serving_cert_key"`
	ServingKeyKey  string `yaml:"serving_key_key"`

	// CertScope and CRLScope select how much of each chain to publish. Empty
	// selects ScopeSelf, which is what makes the fields back-compatible: on
	// today's single-certificate CAs self and chain are byte-identical, so no
	// existing deployment changes.
	//
	// Note the deliberate asymmetry with the HTTP endpoints. GET /certificate/ca
	// and the CRL endpoint always serve the full chain, because Puppet agents
	// need it; export targets default to self, because they typically feed one
	// consumer's trust bundle where a whole chain is rarely what is wanted.
	CertScope string `yaml:"cert_scope"`
	CRLScope  string `yaml:"crl_scope"`
}

// wantsServingKey reports whether any target publishes the serving private key.
// Used at startup to warn that an encrypted key is decrypted before publishing.
func (c *Config) wantsServingKey() bool {
	for i := range c.Targets {
		if c.Targets[i].ServingKey {
			return true
		}
	}
	return false
}

// WantsServingKey reports whether any target publishes the serving private key.
func (c *Config) WantsServingKey() bool { return c != nil && c.wantsServingKey() }

// Enabled reports whether any export target is configured.
func (c *Config) Enabled() bool {
	return c != nil && len(c.Targets) > 0
}

// Validate normalises the config in place (canonicalising kinds, applying
// defaults) and returns an error describing the first invalid target. It is
// safe to call once at startup before constructing an Exporter.
func (c *Config) Validate() error {
	if c.FieldManager == "" {
		c.FieldManager = defaultFieldManager
	}
	for i := range c.Targets {
		if err := c.Targets[i].validate(); err != nil {
			return fmt.Errorf("kubernetes_export target %d: %w", i, err)
		}
	}
	return nil
}

func (t *Target) validate() error {
	t.Kind = strings.TrimSpace(t.Kind)
	switch {
	case strings.EqualFold(t.Kind, KindSecret):
		t.Kind = KindSecret
	case strings.EqualFold(t.Kind, KindConfigMap):
		t.Kind = KindConfigMap
	case t.Kind == "":
		return fmt.Errorf("kind is required (%q or %q)", KindSecret, KindConfigMap)
	default:
		return fmt.Errorf("invalid kind %q (must be %q or %q)", t.Kind, KindSecret, KindConfigMap)
	}

	if strings.TrimSpace(t.Metadata.Name) == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if !t.Cert && !t.CRL && !t.ServingCert && !t.ServingKey {
		return fmt.Errorf("at least one of cert, crl, serving_cert or serving_key must be true")
	}
	if t.Type != "" && t.Kind != KindSecret {
		return fmt.Errorf("type is only valid for Secret targets")
	}

	// A ConfigMap is world-readable to anything that can get it and is not
	// encrypted at rest. A private key does not belong in one.
	if t.ServingKey && t.Kind != KindSecret {
		return fmt.Errorf("serving_key is only valid for Secret targets, not a %s", t.Kind)
	}

	// SECURITY: a Secret holding ca.crt is routinely mounted widely — it is
	// public trust material and workloads across the cluster read it. Letting
	// it quietly acquire a tls.key entry would extend the serving key's reach
	// to every one of them. Two targets cost nothing.
	if t.ServingKey && (t.Cert || t.CRL) {
		return fmt.Errorf("serving_key cannot be combined with cert or crl in one target: " +
			"a Secret carrying public trust material is mounted far more widely than " +
			"one carrying a private key. Use two targets")
	}

	if t.Cert && t.CertKey == "" {
		t.CertKey = defaultCertKey
	}
	if t.CRL && t.CRLKey == "" {
		t.CRLKey = defaultCRLKey
	}
	if t.ServingCert && t.ServingCertKey == "" {
		t.ServingCertKey = defaultServingCertKey
	}
	if t.ServingKey && t.ServingKeyKey == "" {
		t.ServingKeyKey = defaultServingKeyKey
	}

	if t.CertScope == "" {
		t.CertScope = ScopeSelf
	}
	if t.CRLScope == "" {
		t.CRLScope = ScopeSelf
	}
	switch t.CertScope {
	case ScopeSelf, ScopeChain, ScopeRoot:
	default:
		return fmt.Errorf("invalid cert_scope %q (must be %q, %q or %q)",
			t.CertScope, ScopeSelf, ScopeChain, ScopeRoot)
	}
	switch t.CRLScope {
	case ScopeSelf, ScopeChain:
	default:
		// No "root" for CRLs: a chain has no single anchor CRL, and the root's
		// own CRL is just one of its members.
		return fmt.Errorf("invalid crl_scope %q (must be %q or %q)",
			t.CRLScope, ScopeSelf, ScopeChain)
	}

	// A single object cannot store two materials under the same key. Checked
	// across every requested pair rather than just cert/crl, because the
	// defaults now come from two different conventions and an operator
	// overriding one could collide with any of the others.
	if err := t.checkDistinctKeys(); err != nil {
		return err
	}
	return nil
}

// checkDistinctKeys reports the first data key claimed by two materials.
func (t *Target) checkDistinctKeys() error {
	seen := make(map[string]string, 4)
	for _, e := range []struct {
		want bool
		name string
		key  string
	}{
		{t.Cert, "cert_key", t.CertKey},
		{t.CRL, "crl_key", t.CRLKey},
		{t.ServingCert, "serving_cert_key", t.ServingCertKey},
		{t.ServingKey, "serving_key_key", t.ServingKeyKey},
	} {
		if !e.want {
			continue
		}
		if prev, ok := seen[e.key]; ok {
			return fmt.Errorf("%s and %s must differ (both %q)", prev, e.name, e.key)
		}
		seen[e.key] = e.name
	}
	return nil
}
