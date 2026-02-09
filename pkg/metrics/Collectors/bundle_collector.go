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

package collectors

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/compat"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	caSSLNotBefore = prometheus.NewDesc("certmanager_ssl_ca_not_before", "A Unix timestamp of the date when the CA validity begins", []string{"serial_number", "subject_common_name", "bundle_name", "source_kind", "source_name", "source_key"}, nil)
	caSSLNotAfter  = prometheus.NewDesc("certmanager_ssl_ca_not_after", "A Unix timestamp of the date when the CA validity ends", []string{"serial_number", "subject_common_name", "bundle_name", "source_kind", "source_name", "source_key"}, nil)
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
	client               client.Client
	caSSlNotBeforeMetric *prometheus.Desc
	caSSlNotAfterMetric  *prometheus.Desc
}

func NewBundleCollector(log logr.Logger, client client.Client) prometheus.Collector {
	log.WithName("Metrics")
	return &BundleCollector{
		log,
		client,
		caSSLNotBefore,
		caSSLNotAfter,
	}
}

func (bc BundleCollector) Describe(desc chan<- *prometheus.Desc) {
	desc <- bc.caSSlNotBeforeMetric
	desc <- bc.caSSlNotAfterMetric
}

func (bc BundleCollector) Collect(ch chan<- prometheus.Metric) {
	bundles := v1alpha1.BundleList{}
	err := bc.client.List(context.TODO(), &bundles)
	if err != nil {
		return
	}

	bc.updateNotBeforeAndNotAfter(ch, bundles)
}

func (bc BundleCollector) updateNotBeforeAndNotAfter(ch chan<- prometheus.Metric, bundles v1alpha1.BundleList) {
	for i := range bundles.Items {
		bundle := bundles.Items[i]

		var cert *x509.Certificate
		var name, key string
		var kind Kind
		var err error

		for j := range bundle.Spec.Sources {
			s := bundle.Spec.Sources[j]

			switch {
			case s.Secret != nil:
				name, key, kind = s.Secret.Name, s.Secret.Key, SecretKind
				cert, err = bc.getCertificateFromSecret(bundle.Namespace, name, key)
				if err != nil {
					bc.logger.Info("failed to get certificate from secret", "secret", client.ObjectKey{Namespace: bundle.Namespace, Name: name}, "error", err)
					continue
				}
			case s.ConfigMap != nil:
				name, key, kind = s.ConfigMap.Name, s.ConfigMap.Key, ConfigMapKind
				cert, err = bc.getCertificateFromConfigMap(bundle.Namespace, name, key)
				if err != nil {
					bc.logger.Info("failed to get certificate from configmap", "configmap", client.ObjectKey{Namespace: bundle.Namespace, Name: name}, "error", err)
					continue
				}
			case s.InLine != nil:
				name, key, kind = "inline", "inline", InlineKind
				cert, err = compat.ParseCertificate([]byte(*s.InLine))
				if err != nil {
					bc.logger.Info("failed to parse inline certificate", "error", err)
					continue

				}
			}

			if cert == nil {
				bc.logger.V(5).Info("failed to get certificate from source", "source", s)
				continue
			}

			ch <- prometheus.MustNewConstMetric(
				bc.caSSlNotAfterMetric,
				prometheus.GaugeValue,
				float64(cert.NotAfter.Unix()),
				cert.SerialNumber.String(),
				cert.Subject.CommonName,
				bundle.Name,
				string(kind),
				name,
				key,
			)
			ch <- prometheus.MustNewConstMetric(
				bc.caSSlNotBeforeMetric,
				prometheus.GaugeValue,
				float64(cert.NotBefore.Unix()),
				cert.SerialNumber.String(),
				cert.Subject.CommonName,
				bundle.Name,
				string(kind),
				name,
				key,
			)
		}
	}
}

func (bc BundleCollector) getCertificateFromSecret(namespace, name, key string) (*x509.Certificate, error) {
	secret := corev1.Secret{}
	err := bc.client.Get(context.TODO(), client.ObjectKey{Namespace: namespace, Name: name}, &secret)
	if err != nil {
		return nil, err
	}

	caData, ok := secret.Data[key]
	if !ok || len(caData) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	return compat.ParseCertificate(caData)
}

func (bc BundleCollector) getCertificateFromConfigMap(namespace, name, key string) (*x509.Certificate, error) {
	configMap := corev1.ConfigMap{}
	err := bc.client.Get(context.TODO(), client.ObjectKey{Namespace: namespace, Name: name}, &configMap)
	if err != nil {
		return nil, err
	}

	caData, ok := configMap.Data[key]
	if !ok || len(caData) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	return compat.ParseCertificate([]byte(caData))
}
