/*
Copyright 2022 The cert-manager Authors.

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

package source

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

type SecretGetter struct {
	Client    client.Reader
	Namespace string
}

func (sg *SecretGetter) Get(ctx context.Context, ref *trustapi.SourceObjectKeySelector) ([]corev1.Secret, error) {
	if ref.Name != "" {
		secret := corev1.Secret{}
		if err := sg.Client.Get(ctx, client.ObjectKey{
			Namespace: sg.Namespace,
			Name:      ref.Name,
		}, &secret); err != nil {
			err = fmt.Errorf("failed to get Secret %s/%s: %w", sg.Namespace, ref.Name, err)
			if apierrors.IsNotFound(err) {
				err = NotFoundError{err}
			}
			return nil, err
		}

		return []corev1.Secret{secret}, nil
	}
	// if Selector is set, we `List` by label selector
	sl := corev1.SecretList{}
	selector, selectorErr := metav1.LabelSelectorAsSelector(ref.Selector)
	if selectorErr != nil {
		return nil, fmt.Errorf("failed to parse label selector as Selector for Secret in namespace %s: %w", sg.Namespace, selectorErr)
	}
	if err := sg.Client.List(ctx, &sl, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, fmt.Errorf("failed to get SecretList: %w", err)
	} else if len(sl.Items) == 0 {
		logf.FromContext(ctx).Info(fmt.Sprintf("label selector %s for Secret didn't match any resources", selector.String()))
		return sl.Items, nil
	}

	return sl.Items, nil
}

type ConfigMapGetter struct {
	Client    client.Reader
	Namespace string
}

func (cg *ConfigMapGetter) Get(ctx context.Context, ref *trustapi.SourceObjectKeySelector) ([]corev1.ConfigMap, error) {
	if ref.Name != "" {
		cm := corev1.ConfigMap{}
		if err := cg.Client.Get(ctx, client.ObjectKey{
			Namespace: cg.Namespace,
			Name:      ref.Name,
		}, &cm); err != nil {
			err = fmt.Errorf("failed to get ConfigMap %s/%s: %w", cg.Namespace, ref.Name, err)
			if apierrors.IsNotFound(err) {
				err = NotFoundError{err}
			}
			return nil, err
		}

		return []corev1.ConfigMap{cm}, nil
	}
	// if Selector is set, we `List` by label selector
	cml := corev1.ConfigMapList{}
	selector, selectorErr := metav1.LabelSelectorAsSelector(ref.Selector)
	if selectorErr != nil {
		return nil, fmt.Errorf("failed to parse label selector as Selector for ConfigMap in namespace %s: %w", cg.Namespace, selectorErr)
	}
	if err := cg.Client.List(ctx, &cml, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, fmt.Errorf("failed to get ConfigMapList: %w", err)
	} else if len(cml.Items) == 0 {
		logf.FromContext(ctx).Info(fmt.Sprintf("label selector %s for ConfigMap didn't match any resources", selector.String()))
		return cml.Items, nil
	}

	return cml.Items, nil
}
