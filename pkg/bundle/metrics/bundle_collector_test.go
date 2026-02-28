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

package metrics

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/controller"
)

func TestBundleCollector_Collect(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := time.Now().Add(time.Hour).Truncate(time.Second)
	certPEM := generateTestCertificate(t, "bundle-ca", notBefore, notAfter)

	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	require.NoError(t, v1.AddToScheme(scheme))

	bundle := &v1alpha1.Bundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-bundle",
			Namespace: "cert-manager",
		},
		Spec: v1alpha1.BundleSpec{
			Sources: []v1alpha1.BundleSource{
				{
					InLine: ptr(string(certPEM)),
				},
				{
					Secret: &v1alpha1.SourceObjectKeySelector{
						Name: "my-secret",
						Key:  "ca.crt",
					},
				},
			},
		},
	}

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "cert-manager",
		},
		Data: map[string][]byte{
			"ca.crt": certPEM,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(bundle, secret).
		Build()

	opts := controller.Options{
		Namespace: "cert-manager",
	}

	bc := NewBundleCollector(log.Log, opts, fakeClient)
	ch := make(chan prometheus.Metric, 10)
	bc.Collect(ch)
	close(ch)

	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}

	// 2 metrics for inline + 2 metrics for secret = 4
	assert.Len(t, metrics, 4)
}

func ptr[T any](v T) *T {
	return &v
}

func generateTestCertificate(t *testing.T, commonName string, notBefore, notAfter time.Time) []byte {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

func getMetricValue(m prometheus.Metric) (float64, error) {
	var metric io_prometheus_client.Metric
	if err := m.Write(&metric); err != nil {
		return 0, err
	}
	return metric.GetGauge().GetValue(), nil
}

func getMetricLabels(m prometheus.Metric) (map[string]string, error) {
	var metric io_prometheus_client.Metric
	if err := m.Write(&metric); err != nil {
		return map[string]string{}, err
	}
	labels := make(map[string]string)
	for _, l := range metric.GetLabel() {
		labels[l.GetName()] = l.GetValue()
	}
	return labels, nil
}

func assertMetricValue(t *testing.T, m prometheus.Metric, expectedNotBefore, expectedNotAfter time.Time) {
	val, err := getMetricValue(m)
	if err != nil {
		t.Errorf("failed to get metric value: %v", err)
	}
	if m.Desc().String() == caSSLNotBefore.String() {
		assert.Equal(t, float64(expectedNotBefore.Unix()), val)
	} else if m.Desc().String() == caSSLNotAfter.String() {
		assert.Equal(t, float64(expectedNotAfter.Unix()), val)
	} else {
		t.Errorf("unexpected metric description: %v", m.Desc())
	}
}

func TestInlineMetricSource_ReportMetrics(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := time.Now().Add(time.Hour).Truncate(time.Second)
	certPEM := generateTestCertificate(t, "test-ca", notBefore, notAfter)

	source := inlineMetricSource{
		data:       certPEM,
		bundleName: "test-bundle",
	}

	ch := make(chan prometheus.Metric, 2)
	source.reportMetrics(ch)
	close(ch)

	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}

	assert.Len(t, metrics, 2)

	for _, m := range metrics {
		labels, err := getMetricLabels(m)
		if err != nil {
			t.Errorf("failed to get metric labels: %v", err)
		}
		assert.Equal(t, "test-ca", labels["subject_common_name"])
		assert.Equal(t, "test-bundle", labels["bundle_name"])
		assert.Equal(t, string(InlineKind), labels["kind"])
		assert.Equal(t, "1", labels["serial_number"])
		assertMetricValue(t, m, notBefore, notAfter)
	}
}

func TestSecretMetricSource_ReportMetrics(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := time.Now().Add(time.Hour).Truncate(time.Second)
	certPEM := generateTestCertificate(t, "secret-ca", notBefore, notAfter)

	t.Run("with specific key", func(t *testing.T) {
		secret := v1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "my-secret"},
			Data: map[string][]byte{
				"ca.crt": certPEM,
				"other":  []byte("not a cert"),
			},
		}

		source := secretMetricSource{
			items: []v1.Secret{secret},
			sourceSelector: &v1alpha1.SourceObjectKeySelector{
				Key: "ca.crt",
			},
			bundleName: "test-bundle",
		}

		ch := make(chan prometheus.Metric, 2)
		source.reportMetrics(ch)
		close(ch)

		var metrics []prometheus.Metric
		for m := range ch {
			metrics = append(metrics, m)
		}

		assert.Len(t, metrics, 2)
		for _, m := range metrics {
			labels, err := getMetricLabels(m)
			if err != nil {
				t.Errorf("failed to get metric labels: %v", err)
			}
			assert.Equal(t, "secret-ca", labels["subject_common_name"])
			assert.Equal(t, "my-secret", labels["name"])
			assert.Equal(t, "ca.crt", labels["key"])
			assert.Equal(t, string(SecretKind), labels["kind"])
			assertMetricValue(t, m, notBefore, notAfter)

		}

	})

	t.Run("without specific key", func(t *testing.T) {
		secret := v1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "my-secret"},
			Data: map[string][]byte{
				"ca.crt": certPEM,
			},
		}

		source := secretMetricSource{
			items:          []v1.Secret{secret},
			sourceSelector: &v1alpha1.SourceObjectKeySelector{},
			bundleName:     "test-bundle",
		}

		ch := make(chan prometheus.Metric, 2)
		source.reportMetrics(ch)
		close(ch)

		var metrics []prometheus.Metric
		for m := range ch {
			metrics = append(metrics, m)
		}

		assert.Len(t, metrics, 2)
		for _, m := range metrics {
			labels, err := getMetricLabels(m)
			if err != nil {
				t.Errorf("failed to get metric labels: %v", err)
			}
			assert.Equal(t, "my-secret", labels["name"])
			assert.Equal(t, "ca.crt", labels["key"])
			assertMetricValue(t, m, notBefore, notAfter)

		}
	})

	t.Run("skip TLS secret without key", func(t *testing.T) {
		secret := v1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-secret"},
			Type:       v1.SecretTypeTLS,
			Data: map[string][]byte{
				v1.TLSCertKey: certPEM,
			},
		}

		source := secretMetricSource{
			items:          []v1.Secret{secret},
			sourceSelector: &v1alpha1.SourceObjectKeySelector{},
			bundleName:     "test-bundle",
		}

		ch := make(chan prometheus.Metric, 2)
		source.reportMetrics(ch)
		close(ch)

		assert.Empty(t, ch)
	})
}

func TestConfigMapMetricSource_ReportMetrics(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := time.Now().Add(time.Hour).Truncate(time.Second)
	certPEM := generateTestCertificate(t, "cm-ca", notBefore, notAfter)

	t.Run("with specific key", func(t *testing.T) {
		cm := v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cm"},
			Data: map[string]string{
				"ca.crt": string(certPEM),
			},
		}

		source := configMapMetricSource{
			items: []v1.ConfigMap{cm},
			sourceSelector: &v1alpha1.SourceObjectKeySelector{
				Key: "ca.crt",
			},
			bundleName: "test-bundle",
		}

		ch := make(chan prometheus.Metric, 2)
		source.reportMetrics(ch)
		close(ch)

		var metrics []prometheus.Metric
		for m := range ch {
			metrics = append(metrics, m)
		}

		assert.Len(t, metrics, 2)
		for _, m := range metrics {
			labels, err := getMetricLabels(m)
			if err != nil {
				t.Errorf("failed to get metric labels: %v", err)
			}
			assert.Equal(t, "cm-ca", labels["subject_common_name"])
			assert.Equal(t, "my-cm", labels["name"])
			assert.Equal(t, "ca.crt", labels["key"])
			assert.Equal(t, string(ConfigMapKind), labels["kind"])
			assertMetricValue(t, m, notBefore, notAfter)
		}
	})

	t.Run("without specific key", func(t *testing.T) {
		cm := v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cm"},
			Data: map[string]string{
				"ca.crt": string(certPEM),
			},
		}

		source := configMapMetricSource{
			items:          []v1.ConfigMap{cm},
			sourceSelector: &v1alpha1.SourceObjectKeySelector{},
			bundleName:     "test-bundle",
		}

		ch := make(chan prometheus.Metric, 2)
		source.reportMetrics(ch)
		close(ch)

		var metrics []prometheus.Metric
		for m := range ch {
			metrics = append(metrics, m)
		}

		assert.Len(t, metrics, 2)
		for _, m := range metrics {
			labels, err := getMetricLabels(m)
			if err != nil {
				t.Errorf("failed to get metric labels: %v", err)
			}
			assert.Equal(t, "my-cm", labels["name"])
			assert.Equal(t, "ca.crt", labels["key"])
			assertMetricValue(t, m, notBefore, notAfter)

		}
	})
}
