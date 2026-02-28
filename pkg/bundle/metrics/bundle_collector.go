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
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/controller"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/source"
	"github.com/cert-manager/trust-manager/pkg/compat"
)

var (
	caSSLNotBefore = prometheus.NewDesc("certmanager_ssl_ca_not_before", "A Unix timestamp of the date when the CA validity begins", []string{"serial_number", "subject_common_name", "bundle_name", "kind", "name", "key"}, nil)
	caSSLNotAfter  = prometheus.NewDesc("certmanager_ssl_ca_not_after", "A Unix timestamp of the date when the CA validity ends", []string{"serial_number", "subject_common_name", "bundle_name", "kind", "name", "key"}, nil)
)

type Kind string

var (
	SecretKind    Kind = "Secret"
	ConfigMapKind Kind = "ConfigMap"
	InlineKind    Kind = "Inline"
	DefaultKind   Kind = "Default"
)

type BundleCollector struct {
	logger               logr.Logger
	opts                 controller.Options
	client               client.Client
	secretGetter         source.SecretGetter
	configMapGetter      source.ConfigMapGetter
	caSSlNotBeforeMetric *prometheus.Desc
	caSSlNotAfterMetric  *prometheus.Desc
}

func NewBundleCollector(log logr.Logger, opts controller.Options, client client.Client) prometheus.Collector {
	log.WithName("Metrics")
	return &BundleCollector{
		logger:               log,
		opts:                 opts,
		client:               client,
		secretGetter:         source.SecretGetter{Client: client, Namespace: opts.Namespace},
		configMapGetter:      source.ConfigMapGetter{Client: client, Namespace: opts.Namespace},
		caSSlNotBeforeMetric: caSSLNotBefore,
		caSSlNotAfterMetric:  caSSLNotAfter,
	}
}

func (bc BundleCollector) Describe(desc chan<- *prometheus.Desc) {
	desc <- bc.caSSlNotBeforeMetric
	desc <- bc.caSSlNotAfterMetric
}

func (bc BundleCollector) Collect(ch chan<- prometheus.Metric) {
	bundles := v1alpha1.BundleList{}
	ctx := context.Background()
	err := bc.client.List(ctx, &bundles, client.InNamespace(bc.opts.Namespace))
	if err != nil {
		return
	}

	bc.collectNotBeforeAndNotAfter(ctx, ch, bundles)
}

func (bc BundleCollector) collectNotBeforeAndNotAfter(ctx context.Context, ch chan<- prometheus.Metric, bundles v1alpha1.BundleList) {
	for i := range bundles.Items {
		bundle := bundles.Items[i]
		var reporter metricReporter

		for j := range bundle.Spec.Sources {
			s := bundle.Spec.Sources[j]

			switch {
			case s.Secret != nil:
				secrets, err := bc.secretGetter.Get(ctx, s.Secret)
				if err != nil || len(secrets) == 0 {
					continue
				}
				reporter = secretMetricSource{items: secrets, sourceSelector: s.Secret, bundleName: bundle.Name}
			case s.ConfigMap != nil:
				configMaps, err := bc.configMapGetter.Get(ctx, s.ConfigMap)
				if err != nil || len(configMaps) == 0 {
					continue
				}
				reporter = configMapMetricSource{items: configMaps, sourceSelector: s.ConfigMap, bundleName: bundle.Name}
			case s.InLine != nil:
				reporter = inlineMetricSource{data: []byte(*s.InLine), bundleName: bundle.Name}
			case s.UseDefaultCAs != nil:
				//
			}

			reporter.reportMetrics(ch)
		}
	}
}

func parseCertificate(pemData []byte) (*x509.Certificate, error) {
	if pemData == nil {
		return nil, fmt.Errorf("certificate data can't be nil")
	}

	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)

		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			// only certificates are allowed in a bundle
			return nil, fmt.Errorf("invalid PEM block in bundle: only CERTIFICATE blocks are permitted but found '%s'", block.Type)
		}

		if len(block.Headers) != 0 {
			return nil, fmt.Errorf("invalid PEM block in bundle; blocks are not permitted to have PEM headers")
		}

		certificate, err := compat.ParseCertificate(block.Bytes)
		if err != nil {
			if compat.IsSkipError(err) {
				continue
			}

			// the presence of an invalid cert (including things which aren't certs)
			// should cause the bundle to be rejected
			return nil, fmt.Errorf("invalid PEM block in bundle; invalid PEM certificate: %w", err)
		}

		if certificate == nil {
			return nil, fmt.Errorf("failed appending a certificate: certificate is nil")
		}
		return certificate, nil
	}
	return nil, fmt.Errorf("failed to parse certificate")
}

type metricReporter interface {
	reportMetrics(ch chan<- prometheus.Metric)
}

func buildMetric(cert *x509.Certificate, bundleName string, kind Kind, key, name string) []prometheus.Metric {
	metrics := make([]prometheus.Metric, 0, 2)
	notAfter := prometheus.MustNewConstMetric(
		caSSLNotAfter,
		prometheus.GaugeValue,
		float64(cert.NotAfter.Unix()),
		cert.SerialNumber.String(),
		cert.Subject.CommonName,
		bundleName,
		string(kind),
		name,
		key,
	)
	metrics = append(metrics, notAfter)
	notBefore := prometheus.MustNewConstMetric(
		caSSLNotBefore,
		prometheus.GaugeValue,
		float64(cert.NotBefore.Unix()),
		cert.SerialNumber.String(),
		cert.Subject.CommonName,
		bundleName,
		string(kind),
		name,
		key,
	)
	metrics = append(metrics, notBefore)
	return metrics
}

type secretMetricSource struct {
	items          []v1.Secret
	sourceSelector *v1alpha1.SourceObjectKeySelector
	bundleName     string
}

func (s secretMetricSource) reportMetrics(ch chan<- prometheus.Metric) {
	var metrics []prometheus.Metric
	for i := range s.items {
		item := s.items[i]
		if len(s.sourceSelector.Key) > 0 {
			data, ok := item.Data[s.sourceSelector.Key]
			if !ok {
				continue
			}
			cert, err := parseCertificate(data)
			if err != nil {
				continue
			}
			metrics = buildMetric(cert, s.bundleName, SecretKind, s.sourceSelector.Key, item.Name)
		} else {
			if item.Type == v1.SecretTypeTLS {
				continue
			}

			for key, data := range item.Data {
				certificate, err := parseCertificate(data)
				if err != nil {
					continue
				}
				metrics = append(metrics, buildMetric(certificate, s.bundleName, SecretKind, key, item.Name)...)
			}
		}
	}

	for _, v := range metrics {
		ch <- v
	}
}

type configMapMetricSource struct {
	items          []v1.ConfigMap
	sourceSelector *v1alpha1.SourceObjectKeySelector
	bundleName     string
}

func (s configMapMetricSource) reportMetrics(ch chan<- prometheus.Metric) {
	var metrics []prometheus.Metric
	for i := range s.items {
		item := s.items[i]
		if len(s.sourceSelector.Key) > 0 {
			data, ok := item.Data[s.sourceSelector.Key]
			if !ok {
				continue
			}
			cert, err := parseCertificate([]byte(data))
			if err != nil {
				continue
			}
			metrics = buildMetric(cert, s.bundleName, ConfigMapKind, s.sourceSelector.Key, item.Name)
		} else {
			for key, data := range item.Data {
				certificate, err := parseCertificate([]byte(data))
				if err != nil {
					continue
				}
				metrics = append(metrics, buildMetric(certificate, s.bundleName, ConfigMapKind, key, item.Name)...)
			}
		}
	}

	for _, v := range metrics {
		ch <- v
	}
}

type inlineMetricSource struct {
	data       []byte
	bundleName string
}

func (c inlineMetricSource) reportMetrics(ch chan<- prometheus.Metric) {
	cert, err := parseCertificate(c.data)
	if err != nil {
		return
	}

	metrics := buildMetric(cert, c.bundleName, InlineKind, "", "")

	for _, v := range metrics {
		ch <- v
	}
}
