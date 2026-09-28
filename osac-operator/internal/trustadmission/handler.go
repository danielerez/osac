/*
Copyright 2026.

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

package trustadmission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	TrustSyncServiceAccount = "osac-fulfillment-trust-sync"
	TrustClientLabel        = "osac.openshift.io/fulfillment-trust-client"
)

var errInvalidHandlerConfig = errors.New("invalid tenant trust admission configuration")

type Config struct {
	TenantNamespace string
	Now             func() time.Time
}

type Handler struct {
	store                 Store
	tenantNamespace       string
	now                   func() time.Time
	trustedServiceAccount string
}

func NewHandler(store Store, config Config) (*Handler, error) {
	if store == nil || config.TenantNamespace == "" {
		return nil, errInvalidHandlerConfig
	}
	if config.Now == nil {
		config.Now = time.Now
	}

	return &Handler{
		store:                 store,
		tenantNamespace:       config.TenantNamespace,
		now:                   config.Now,
		trustedServiceAccount: fmt.Sprintf("system:serviceaccount:%s:%s", config.TenantNamespace, TrustSyncServiceAccount),
	}, nil
}

func (h *Handler) Handle(_ context.Context, request admission.Request) admission.Response {
	// A validating webhook is cluster scoped. Requests outside this admission
	// service's tenant namespace must be ignored before checking the caller so
	// this tenant-specific policy cannot deny unrelated tenant workloads.
	if request.Namespace != "" && request.Namespace != h.tenantNamespace {
		return admission.Allowed("")
	}

	if request.UserInfo.Username != h.trustedServiceAccount {
		return denied()
	}

	switch {
	case isConfigMapRequest(request):
		return h.handleConfigMap(request)
	case isDeploymentRequest(request):
		return h.handleDeployment(request)
	default:
		return denied()
	}
}

func (h *Handler) handleConfigMap(request admission.Request) admission.Response {
	if request.Operation != admissionv1.Create && request.Operation != admissionv1.Update {
		return denied()
	}

	candidate := &corev1.ConfigMap{}
	if err := json.Unmarshal(request.Object.Raw, candidate); err != nil || candidate.Namespace != h.tenantNamespace || h.store.AuthorizeConfigMap(candidate, h.now()) != nil {
		return denied()
	}
	return admission.Allowed("")
}

func (h *Handler) handleDeployment(request admission.Request) admission.Response {
	if request.Operation != admissionv1.Update {
		return denied()
	}

	oldDeployment := &appsv1.Deployment{}
	newDeployment := &appsv1.Deployment{}
	if err := json.Unmarshal(request.OldObject.Raw, oldDeployment); err != nil {
		return denied()
	}
	if err := json.Unmarshal(request.Object.Raw, newDeployment); err != nil {
		return denied()
	}
	if oldDeployment.Namespace != h.tenantNamespace || oldDeployment.Labels[TrustClientLabel] != "true" || !onlyBundleHashChanged(oldDeployment, newDeployment) {
		return denied()
	}

	bundleHash := newDeployment.Spec.Template.Annotations[BundleHashAnnotation]
	if h.store.AuthorizeDeployment(newDeployment.Namespace, bundleHash, h.now()) != nil {
		return denied()
	}
	return admission.Allowed("")
}

func isConfigMapRequest(request admission.Request) bool {
	return request.Resource.Group == "" && request.Resource.Version == "v1" && request.Resource.Resource == "configmaps" && request.Kind.Group == "" && request.Kind.Version == "v1" && request.Kind.Kind == "ConfigMap"
}

func isDeploymentRequest(request admission.Request) bool {
	return request.Resource.Group == "apps" && request.Resource.Version == "v1" && request.Resource.Resource == "deployments" && request.Kind.Group == "apps" && request.Kind.Version == "v1" && request.Kind.Kind == "Deployment"
}

func onlyBundleHashChanged(oldDeployment, newDeployment *appsv1.Deployment) bool {
	bundleHash := newDeployment.Spec.Template.Annotations[BundleHashAnnotation]
	if bundleHash == "" {
		return false
	}

	oldCopy := oldDeployment.DeepCopy()
	newCopy := newDeployment.DeepCopy()
	normalizeDeploymentMetadata(oldCopy)
	normalizeDeploymentMetadata(newCopy)
	oldCopy.Spec.Template.Annotations = withoutBundleHash(oldCopy.Spec.Template.Annotations)
	newCopy.Spec.Template.Annotations = withoutBundleHash(newCopy.Spec.Template.Annotations)

	return reflect.DeepEqual(oldCopy, newCopy)
}

func normalizeDeploymentMetadata(deployment *appsv1.Deployment) {
	normalizeObjectMeta(&deployment.ObjectMeta)
	normalizeObjectMeta(&deployment.Spec.Template.ObjectMeta)
}

func normalizeObjectMeta(metadata *metav1.ObjectMeta) {
	metadata.ResourceVersion = ""
	metadata.Generation = 0
	metadata.CreationTimestamp = metav1.Time{}
	metadata.DeletionTimestamp = nil
	metadata.DeletionGracePeriodSeconds = nil
	metadata.ManagedFields = nil
}

func withoutBundleHash(annotations map[string]string) map[string]string {
	copy := maps.Clone(annotations)
	delete(copy, BundleHashAnnotation)
	if len(copy) == 0 {
		return nil
	}
	return copy
}

func denied() admission.Response {
	return admission.Denied("tenant trust admission denied")
}
