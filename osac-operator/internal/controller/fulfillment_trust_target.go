package controller

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"strconv"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/osac-project/osac/osac-operator/api/v1alpha1"
	"github.com/osac-project/osac/osac-operator/internal/trustadmission"
)

const (
	trustCredentialsPrefix      = "fulfillment-trust-"
	trustObserverKubeconfigKey  = "observerKubeconfig"
	trustPublisherKubeconfigKey = "publisherKubeconfig"
	trustAAPCredentialIDKey     = "aapCredentialID"
	trustAAPCredentialRefKey    = "aapCredentialRef"
)

// SecretTrustTargetResolver reads per-ClusterOrder protected references from a
// management Secret. The two kubeconfigs must identify the guest cluster's
// observer and publisher service accounts, respectively.
type SecretTrustTargetResolver struct {
	Management      client.Reader
	Namespace       string
	TenantNamespace string
}

func (r *SecretTrustTargetResolver) Resolve(ctx context.Context, order *v1alpha1.ClusterOrder) (FulfillmentTrustTarget, error) {
	if r.Management == nil || order == nil || order.UID == "" || r.Namespace == "" || r.TenantNamespace == "" {
		return nil, fmt.Errorf("protected trust target is not configured")
	}
	secret := &corev1.Secret{}
	name := trustCredentialsPrefix + string(order.UID)
	if err := r.Management.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: name}, secret); err != nil {
		return nil, err
	}
	if secret.Annotations[trustadmission.OwnerReferenceAnnotation] != string(order.UID) ||
		secret.Annotations[trustadmission.TenantAnnotation] != order.Annotations[trustadmission.TenantAnnotation] {
		return nil, fmt.Errorf("protected trust credentials do not match ClusterOrder")
	}
	id, err := strconv.Atoi(string(secret.Data[trustAAPCredentialIDKey]))
	if err != nil || id <= 0 || len(secret.Data[trustAAPCredentialRefKey]) == 0 {
		return nil, fmt.Errorf("protected AAP credential reference is invalid")
	}
	observerConfig, err := clientcmd.RESTConfigFromKubeConfig(secret.Data[trustObserverKubeconfigKey])
	if err != nil {
		return nil, fmt.Errorf("protected observer credential is invalid: %w", err)
	}
	if err := validateTrustServiceAccountConfig(observerConfig); err != nil {
		return nil, fmt.Errorf("protected observer credential is invalid: %w", err)
	}
	publisherConfig, err := clientcmd.RESTConfigFromKubeConfig(secret.Data[trustPublisherKubeconfigKey])
	if err != nil {
		return nil, fmt.Errorf("protected publisher credential is invalid: %w", err)
	}
	if err := validateTrustServiceAccountConfig(publisherConfig); err != nil {
		return nil, fmt.Errorf("protected publisher credential is invalid: %w", err)
	}
	if observerConfig.BearerToken == publisherConfig.BearerToken {
		return nil, fmt.Errorf("observer and publisher credentials must be distinct")
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	observer, err := client.New(observerConfig, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create tenant trust observer: %w", err)
	}
	publisher, err := trustadmission.NewControlClient(publisherConfig, r.TenantNamespace)
	if err != nil {
		return nil, fmt.Errorf("create tenant trust publisher: %w", err)
	}
	observerClientset, err := kubernetes.NewForConfig(observerConfig)
	if err != nil {
		return nil, fmt.Errorf("create tenant trust watch client: %w", err)
	}
	return &KubernetesTrustTarget{
		Observer: observer, Publisher: publisher, Namespace: r.TenantNamespace,
		Watcher: observerClientset, CredentialVersion: secret.ResourceVersion,
		AAPCredentialID: id, AAPCredentialRef: string(secret.Data[trustAAPCredentialRefKey]),
	}, nil
}

func validateTrustServiceAccountConfig(config *rest.Config) error {
	if config == nil {
		return fmt.Errorf("missing Kubernetes connection")
	}
	endpoint, err := url.Parse(config.Host)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || config.Insecure ||
		len(config.CAData) == 0 || config.BearerToken == "" || config.BearerTokenFile != "" ||
		config.ExecProvider != nil || config.AuthProvider != nil || config.Username != "" || config.Password != "" ||
		len(config.CertData) != 0 || len(config.KeyData) != 0 || config.CertFile != "" || config.KeyFile != "" ||
		config.Impersonate.UserName != "" {
		return fmt.Errorf("a TLS-verified service-account token is required")
	}
	return nil
}

// KubernetesTrustTarget reads tenant state through the observer identity and
// writes expected records through the separate publisher identity.
type KubernetesTrustTarget struct {
	Observer  client.Reader
	Publisher interface {
		Publish(context.Context, trustadmission.ExpectedBundle) error
		Revoke(context.Context, trustadmission.RecordKey) error
	}
	Namespace         string
	Watcher           kubernetes.Interface
	CredentialVersion string
	AAPCredentialID   int
	AAPCredentialRef  string
}

// WatchTarget observes relevant tenant changes through the read-only identity.
// The reconciler also polls, covering watch reconnects and missed events.
func (t *KubernetesTrustTarget) WatchTarget(ctx context.Context, notify func()) {
	if t.Watcher == nil {
		return
	}
	watchers := []func(context.Context) (watch.Interface, error){
		func(ctx context.Context) (watch.Interface, error) {
			return t.Watcher.CoreV1().ConfigMaps(t.Namespace).Watch(ctx, metav1.ListOptions{
				FieldSelector: "metadata.name=" + trustadmission.ConfigMapName,
			})
		},
		func(ctx context.Context) (watch.Interface, error) {
			return t.Watcher.AppsV1().Deployments(t.Namespace).Watch(ctx, metav1.ListOptions{
				LabelSelector: trustCSINameLabel + "=csi-driver," + trustCSIComponentLabel + "=controller",
			})
		},
		func(ctx context.Context) (watch.Interface, error) {
			return t.Watcher.AppsV1().ReplicaSets(t.Namespace).Watch(ctx, metav1.ListOptions{})
		},
		func(ctx context.Context) (watch.Interface, error) {
			return t.Watcher.CoreV1().Pods(t.Namespace).Watch(ctx, metav1.ListOptions{})
		},
	}
	for _, start := range watchers {
		go runTrustWatch(ctx, start, notify)
	}
}

func runTrustWatch(ctx context.Context, start func(context.Context) (watch.Interface, error), notify func()) {
	for ctx.Err() == nil {
		stream, err := start(ctx)
		if err == nil {
			func() {
				defer stream.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case event, open := <-stream.ResultChan():
						if !open || event.Type == watch.Error {
							return
						}
						notify()
					}
				}
			}()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (t *KubernetesTrustTarget) CredentialID() int     { return t.AAPCredentialID }
func (t *KubernetesTrustTarget) CredentialRef() string { return t.AAPCredentialRef }

func (t *KubernetesTrustTarget) Publish(ctx context.Context, record trustadmission.ExpectedBundle) error {
	return t.Publisher.Publish(ctx, record)
}

func (t *KubernetesTrustTarget) Revoke(ctx context.Context, key trustadmission.RecordKey) error {
	return t.Publisher.Revoke(ctx, key)
}

// Observe reports whether the exact approved ConfigMap and every CSI controller
// candidate have converged. An unlabelled candidate is a distinct failure.
func (t *KubernetesTrustTarget) Observe(ctx context.Context, expected trustadmission.ExpectedBundle) (bool, bool, error) {
	configMap := &corev1.ConfigMap{}
	err := t.Observer.Get(ctx, types.NamespacedName{Namespace: t.Namespace, Name: trustadmission.ConfigMapName}, configMap)
	if err != nil && !apierrors.IsNotFound(err) {
		return false, false, err
	}
	configMapCurrent := err == nil && len(configMap.Data) == 1 && len(configMap.BinaryData) == 0 &&
		configMap.Data[trustadmission.BundleDataKey] == string(expected.BundlePEM) &&
		maps.Equal(configMap.Annotations, map[string]string{
			trustadmission.TenantAnnotation:         expected.Tenant,
			trustadmission.OwnerReferenceAnnotation: expected.OwnerReference,
			trustadmission.BundleHashAnnotation:     expected.Key.BundleSHA256,
		})
	deployments := &appsv1.DeploymentList{}
	if err := t.Observer.List(ctx, deployments, client.InNamespace(t.Namespace), client.MatchingLabels{
		trustCSINameLabel: "csi-driver", trustCSIComponentLabel: "controller",
	}); err != nil {
		return false, false, err
	}
	current := configMapCurrent
	for i := range deployments.Items {
		deployment := &deployments.Items[i]
		if deployment.Labels[trustadmission.TrustClientLabel] != labelValueTrue {
			return false, true, nil
		}
		if deployment.Spec.Template.Annotations[trustadmission.BundleHashAnnotation] != expected.Key.BundleSHA256 ||
			!trustDeploymentReady(deployment) {
			current = false
		}
		oldReady, err := t.oldReadyPods(ctx, deployment, expected.Key.BundleSHA256)
		if err != nil {
			return false, false, err
		}
		if oldReady {
			current = false
		}
	}
	return current, false, nil
}

func trustDeploymentReady(deployment *appsv1.Deployment) bool {
	desired := int32(1)
	if deployment.Spec.Replicas != nil {
		desired = *deployment.Spec.Replicas
	}
	return deployment.Status.ObservedGeneration == deployment.Generation &&
		deployment.Status.UpdatedReplicas == desired && deployment.Status.ReadyReplicas == desired &&
		deployment.Status.AvailableReplicas == desired && deployment.Status.UnavailableReplicas == 0
}

func (t *KubernetesTrustTarget) oldReadyPods(ctx context.Context, deployment *appsv1.Deployment, hash string) (bool, error) {
	replicaSets := &appsv1.ReplicaSetList{}
	if err := t.Observer.List(ctx, replicaSets, client.InNamespace(t.Namespace)); err != nil {
		return false, err
	}
	oldUIDs := make(map[types.UID]struct{})
	for i := range replicaSets.Items {
		replicaSet := &replicaSets.Items[i]
		if ownedByUID(replicaSet.OwnerReferences, deployment.UID) &&
			replicaSet.Spec.Template.Annotations[trustadmission.BundleHashAnnotation] != hash {
			if replicaSet.Status.ReadyReplicas > 0 {
				return true, nil
			}
			oldUIDs[replicaSet.UID] = struct{}{}
		}
	}
	if len(oldUIDs) == 0 {
		return false, nil
	}
	pods := &corev1.PodList{}
	if err := t.Observer.List(ctx, pods, client.InNamespace(t.Namespace)); err != nil {
		return false, err
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		for uid := range oldUIDs {
			if ownedByUID(pod.OwnerReferences, uid) && podReady(pod) {
				return true, nil
			}
		}
	}
	return false, nil
}

func ownedByUID(refs []metav1.OwnerReference, uid types.UID) bool {
	for _, ref := range refs {
		if ref.UID == uid {
			return true
		}
	}
	return false
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
