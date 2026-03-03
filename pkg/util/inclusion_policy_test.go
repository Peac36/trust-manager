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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInclusionPolicy_ShouldInclude(t *testing.T) {
	now := time.Now()
	expiredCert := &x509.Certificate{
		NotAfter: now.Add(-time.Hour),
		IsCA:     true,
	}
	validCACert := &x509.Certificate{
		NotAfter: now.Add(time.Hour),
		IsCA:     true,
	}
	validNonCACert := &x509.Certificate{
		NotAfter: now.Add(time.Hour),
		IsCA:     false,
	}

	tests := []struct {
		name   string
		policy InclusionPolicy
		cert   *x509.Certificate
		want   bool
	}{
		{
			name:   "include all by default",
			policy: InclusionPolicy{},
			cert:   expiredCert,
			want:   true,
		},
		{
			name:   "filter expired - expired cert",
			policy: InclusionPolicy{FilterExpired: true},
			cert:   expiredCert,
			want:   false,
		},
		{
			name:   "filter expired - valid cert",
			policy: InclusionPolicy{FilterExpired: true},
			cert:   validCACert,
			want:   true,
		},
		{
			name:   "filter non-CA - non-CA cert",
			policy: InclusionPolicy{FilterNonCACerts: true},
			cert:   validNonCACert,
			want:   false,
		},
		{
			name:   "filter non-CA - CA cert",
			policy: InclusionPolicy{FilterNonCACerts: true},
			cert:   validCACert,
			want:   true,
		},
		{
			name: "both filters - valid CA",
			policy: InclusionPolicy{
				FilterExpired:    true,
				FilterNonCACerts: true,
			},
			cert: validCACert,
			want: true,
		},
		{
			name: "both filters - expired CA",
			policy: InclusionPolicy{
				FilterExpired:    true,
				FilterNonCACerts: true,
			},
			cert: expiredCert,
			want: false,
		},
		{
			name: "both filters - valid non-CA",
			policy: InclusionPolicy{
				FilterExpired:    true,
				FilterNonCACerts: true,
			},
			cert: validNonCACert,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.policy.ShouldInclude(tt.cert)
			assert.Equal(t, tt.want, got)
		})
	}
}
