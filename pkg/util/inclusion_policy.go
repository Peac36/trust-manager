/*
Copyright 2026 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"crypto/x509"
	"time"
)

// InclusionPolicy defines whether a certificate should be included in a bundle.
type InclusionPolicy struct {
	// FilterExpired controls if expired certificates are filtered.
	FilterExpired bool

	// FilterNonCACerts controls if non-CA certificates are filtered.
	FilterNonCACerts bool
}

func NewInclusionPolicy(filterExpired, filterNonCaCerts bool) *InclusionPolicy {
	return &InclusionPolicy{
		FilterExpired:    filterExpired,
		FilterNonCACerts: filterNonCaCerts,
	}
}

// ShouldInclude returns true if the certificate should be included based on the policy.
func (p InclusionPolicy) ShouldInclude(certificate *x509.Certificate) bool {
	if p.FilterExpired && time.Now().After(certificate.NotAfter) {
		return false
	}

	if p.FilterNonCACerts && !certificate.IsCA {
		return false
	}

	return true
}
