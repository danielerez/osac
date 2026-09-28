package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"

	"github.com/osac-project/osac/osac-operator/api/v1alpha1"
	"github.com/osac-project/osac/osac-operator/internal/trustadmission"
	"github.com/osac-project/osac/osac-operator/pkg/aap"
)

const (
	fulfillmentTrustOptInAnnotation = "osac.openshift.io/fulfillment-trust-enabled"
	trustSourceName                 = "ca-bundle"
	trustTemplateName               = "osac-sync-tenant-fulfillment-trust"
	trustRecordLifetime             = 10 * time.Minute
	trustRetryInterval              = 30 * time.Second
	trustCSINameLabel               = "app.kubernetes.io/name"
	trustCSIComponentLabel          = "app.kubernetes.io/component"
)

type FulfillmentTrustAAPClient interface {
	GetTemplate(context.Context, string) (*aap.Template, error)
	LaunchJobTemplate(context.Context, aap.LaunchJobTemplateRequest) (*aap.LaunchJobTemplateResponse, error)
	GetJob(context.Context, string) (*aap.Job, error)
	CancelJob(context.Context, string) error
}

type FulfillmentTrustTarget interface {
	Observe(context.Context, trustadmission.ExpectedBundle) (bool, bool, error)
	Publish(context.Context, trustadmission.ExpectedBundle) error
	Revoke(context.Context, trustadmission.RecordKey) error
	CredentialID() int
	CredentialRef() string
}

type FulfillmentTrustTargetResolver interface {
	Resolve(context.Context, *v1alpha1.ClusterOrder) (FulfillmentTrustTarget, error)
}

// FulfillmentTrustReconciler synchronizes an explicitly opted-in ClusterOrder's
// fulfillment CA. It is not registered while Enabled is false.
type FulfillmentTrustReconciler struct {
	client.Client
	APIReader             client.Reader
	Enabled               bool
	ClusterOrderNamespace string
	SourceNamespace       string
	TenantNamespace       string
	SourceName            string
	TemplateName          string
	AAP                   FulfillmentTrustAAPClient
	Targets               FulfillmentTrustTargetResolver
	MaxJobHistory         int
	PollInterval          time.Duration
	Now                   func() time.Time
	watchMu               sync.Mutex
	watchCtx              context.Context
	watchCancel           map[types.NamespacedName]trustWatchHandle
	targetEvents          chan event.GenericEvent
}

type trustWatchHandle struct {
	version string
	cancel  context.CancelFunc
}

func (r *FulfillmentTrustReconciler) pollInterval() time.Duration {
	if r.PollInterval > 0 {
		return r.PollInterval
	}
	return trustRetryInterval
}

func (r *FulfillmentTrustReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if !r.Enabled {
		return ctrl.Result{}, nil
	}
	order := &v1alpha1.ClusterOrder{}
	if err := r.Get(ctx, req.NamespacedName, order); err != nil {
		if client.IgnoreNotFound(err) == nil {
			r.stopTargetWatch(req.NamespacedName)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if order.Namespace != r.ClusterOrderNamespace || order.Annotations[fulfillmentTrustOptInAnnotation] != labelValueTrue ||
		order.Annotations[trustadmission.TenantAnnotation] == "" ||
		order.Annotations[osacManagementStateAnnotation] == ManagementStateUnmanaged {
		r.stopTargetWatch(req.NamespacedName)
		return ctrl.Result{}, nil
	}
	if r.AAP == nil || r.Targets == nil || r.APIReader == nil || r.TenantNamespace == "" || r.SourceNamespace == "" {
		return ctrl.Result{}, errors.New("fulfillment trust reconciler is not configured")
	}
	if !order.DeletionTimestamp.IsZero() {
		r.stopTargetWatch(req.NamespacedName)
		r.fenceDeletion(ctx, order)
		return ctrl.Result{}, nil
	}
	if order.Status.ClusterReference == nil || order.Status.ClusterReference.HostedClusterName == "" {
		r.stopTargetWatch(req.NamespacedName)
		return r.failed(ctx, order, "KubeconfigNotAvailable", "Tenant cluster is not available")
	}
	return r.reconcileTrust(ctx, req.NamespacedName, order)
}

func (r *FulfillmentTrustReconciler) reconcileTrust(ctx context.Context, key types.NamespacedName, order *v1alpha1.ClusterOrder) (ctrl.Result, error) {
	bundle, hash, err := r.sourceBundle(ctx)
	if err != nil {
		r.stopTargetWatch(key)
		r.fenceUnavailableSource(ctx, order)
		return r.failed(ctx, order, "TrustBundleUnavailable", "Management trust bundle is unavailable")
	}
	target, err := r.Targets.Resolve(ctx, order)
	if err != nil || target == nil || target.CredentialID() <= 0 || target.CredentialRef() == "" {
		r.stopTargetWatch(key)
		return r.failed(ctx, order, "KubeconfigNotAvailable", "Protected tenant trust credentials are unavailable")
	}
	r.ensureTargetWatch(key, target)
	now := r.now()
	record := trustadmission.ExpectedBundle{
		Key: trustadmission.RecordKey{
			ClusterOrderUID: string(order.UID), TenantNamespace: r.TenantNamespace,
			ConfigMapName: trustadmission.ConfigMapName, BundleSHA256: hash,
		},
		Tenant: order.Annotations[trustadmission.TenantAnnotation], OwnerReference: string(order.UID),
		BundlePEM: bundle, ExpiresAt: now.Add(trustRecordLifetime),
	}
	if order.UID == "" {
		return r.failed(ctx, order, "KubeconfigNotAvailable", "ClusterOrder identity is unavailable")
	}
	if active := latestActiveTrustJob(order.Status.FulfillmentTrustJobs); active != nil && active.ConfigVersion != hash {
		oldKey := record.Key
		oldKey.BundleSHA256 = active.ConfigVersion
		if err := target.Revoke(ctx, oldKey); err != nil {
			return r.failed(ctx, order, "TrustBundleApplyFailed", "Previous trust bundle revocation failed")
		}
		if err := r.AAP.CancelJob(ctx, active.JobID); err != nil {
			return r.failed(ctx, order, "TrustBundleApplyFailed", "Previous trust job cancellation failed")
		}
		active.State = v1alpha1.JobStateCanceled
		if err := r.patchStatus(ctx, order); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: r.pollInterval()}, nil
	}
	job := latestTrustJob(order.Status.FulfillmentTrustJobs, hash)
	if job != nil && !job.State.IsTerminal() {
		if err := target.Publish(ctx, record); err != nil {
			return r.failed(ctx, order, "TrustBundleApplyFailed", "Expected trust bundle publication failed")
		}
		return r.pollJob(ctx, order, job)
	}
	current, unsupported, err := target.Observe(ctx, record)
	if err != nil {
		return r.failed(ctx, order, "KubeconfigNotAvailable", "Tenant trust target is unavailable")
	}
	if unsupported {
		return r.failed(ctx, order, "CSIClientUpgradeRequired", "CSI controller does not support fulfillment trust")
	}
	if current && job != nil && job.State.IsSuccessful() {
		order.Status.FulfillmentTrustBundleHash = hash
		order.SetStatusCondition(string(v1alpha1.ClusterOrderConditionFulfillmentTrustReady), metav1.ConditionTrue,
			"Trust bundle and CSI rollout verified", "TrustBundleSynchronized")
		return ctrl.Result{RequeueAfter: r.pollInterval()}, r.patchStatus(ctx, order)
	}
	if job != nil && (job.State == v1alpha1.JobStateFailed || job.State == v1alpha1.JobStateCanceled) &&
		now.Sub(job.Timestamp.Time) < r.pollInterval() {
		return ctrl.Result{RequeueAfter: r.pollInterval()}, nil
	}
	return r.launchTrustJob(ctx, order, target, record, now)
}

func (r *FulfillmentTrustReconciler) fenceUnavailableSource(ctx context.Context, order *v1alpha1.ClusterOrder) {
	job := latestActiveTrustJob(order.Status.FulfillmentTrustJobs)
	if job == nil {
		return
	}
	if target, err := r.Targets.Resolve(ctx, order); err == nil && target != nil {
		key := trustadmission.RecordKey{ClusterOrderUID: string(order.UID), TenantNamespace: r.TenantNamespace,
			ConfigMapName: trustadmission.ConfigMapName, BundleSHA256: job.ConfigVersion}
		if err := target.Revoke(ctx, key); err != nil {
			ctrllog.FromContext(ctx).Error(err, "tenant trust record revocation failed", "clusterOrder", order.Name)
		}
	}
	if err := r.AAP.CancelJob(ctx, job.JobID); err != nil {
		ctrllog.FromContext(ctx).Error(err, "tenant trust job cancellation failed", "clusterOrder", order.Name)
		return
	}
	job.State = v1alpha1.JobStateCanceled
}

func (r *FulfillmentTrustReconciler) launchTrustJob(ctx context.Context, order *v1alpha1.ClusterOrder,
	target FulfillmentTrustTarget, record trustadmission.ExpectedBundle, now time.Time) (ctrl.Result, error) {
	latest := &v1alpha1.ClusterOrder{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(order), latest); err != nil {
		return ctrl.Result{}, err
	}
	if !latest.DeletionTimestamp.IsZero() || latest.UID != order.UID {
		return ctrl.Result{}, nil
	}
	if active := latestActiveTrustJob(latest.Status.FulfillmentTrustJobs); active != nil {
		return ctrl.Result{RequeueAfter: r.pollInterval()}, nil
	}
	if err := target.Publish(ctx, record); err != nil {
		return r.failed(ctx, order, "TrustBundleApplyFailed", "Expected trust bundle publication failed")
	}
	templateName := r.TemplateName
	if templateName == "" {
		templateName = trustTemplateName
	}
	template, err := r.AAP.GetTemplate(ctx, templateName)
	if err != nil || template == nil || template.Type != aap.TemplateTypeJob {
		_ = target.Revoke(ctx, record.Key)
		return r.failed(ctx, order, "TrustBundleApplyFailed", "Trust synchronization template is unavailable")
	}
	response, err := r.AAP.LaunchJobTemplate(ctx, aap.LaunchJobTemplateRequest{
		TemplateID: template.ID, TemplateName: templateName,
		CredentialIDs: []int{target.CredentialID()},
		Sensitive:     true,
		ExtraVars: map[string]any{"osac_job_vars": map[string]any{
			"resource": map[string]any{"metadata": map[string]any{
				"uid": string(order.UID), "name": order.Name, "namespace": order.Namespace,
				"annotations": map[string]string{trustadmission.TenantAnnotation: record.Tenant},
			}},
			"trust_kubeconfig_credential_ref": target.CredentialRef(),
			"fulfillment_trust": map[string]string{
				"tenant_namespace": r.TenantNamespace, "config_map_name": trustadmission.ConfigMapName,
				"bundle_pem": string(record.BundlePEM), "bundle_sha256": record.Key.BundleSHA256,
			},
		}},
	})
	if err != nil || response == nil || response.JobID <= 0 {
		_ = target.Revoke(ctx, record.Key)
		return r.failed(ctx, order, "TrustBundleApplyFailed", "Trust synchronization job launch failed")
	}
	order.Status.FulfillmentTrustJobs = append(order.Status.FulfillmentTrustJobs, v1alpha1.JobStatus{
		JobID: strconv.Itoa(response.JobID), Type: v1alpha1.JobTypeProvision,
		Timestamp: metav1.NewTime(now), State: v1alpha1.JobStatePending, ConfigVersion: record.Key.BundleSHA256,
	})
	r.boundHistory(order)
	order.SetStatusCondition(string(v1alpha1.ClusterOrderConditionFulfillmentTrustReady), metav1.ConditionFalse,
		"Trust synchronization job is pending", "TrustBundleSyncing")
	return ctrl.Result{RequeueAfter: r.pollInterval()}, r.patchStatus(ctx, order)
}

func (r *FulfillmentTrustReconciler) sourceBundle(ctx context.Context) ([]byte, string, error) {
	name := r.SourceName
	if name == "" {
		name = trustSourceName
	}
	configMap := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.SourceNamespace, Name: name}, configMap); err != nil {
		return nil, "", err
	}
	bundle := []byte(configMap.Data[trustadmission.BundleDataKey])
	if len(bundle) == 0 || !x509.NewCertPool().AppendCertsFromPEM(bundle) {
		return nil, "", errors.New("invalid management trust bundle")
	}
	digest := sha256.Sum256(bundle)
	return bundle, hex.EncodeToString(digest[:]), nil
}

func (r *FulfillmentTrustReconciler) pollJob(ctx context.Context, order *v1alpha1.ClusterOrder, job *v1alpha1.JobStatus) (ctrl.Result, error) {
	status, err := r.AAP.GetJob(ctx, job.JobID)
	if err != nil {
		return r.failed(ctx, order, "TrustBundleApplyFailed", "Trust synchronization job status is unavailable")
	}
	switch status.Status {
	case "successful":
		job.State = v1alpha1.JobStateSucceeded
	case "failed", "error":
		job.State = v1alpha1.JobStateFailed
	case "canceled":
		job.State = v1alpha1.JobStateCanceled
	case "running":
		job.State = v1alpha1.JobStateRunning
	default:
		job.State = v1alpha1.JobStatePending
	}
	if job.State == v1alpha1.JobStateFailed || job.State == v1alpha1.JobStateCanceled {
		order.SetStatusCondition(string(v1alpha1.ClusterOrderConditionFulfillmentTrustReady), metav1.ConditionFalse,
			"Trust synchronization job failed", "TrustBundleApplyFailed")
	} else {
		order.SetStatusCondition(string(v1alpha1.ClusterOrderConditionFulfillmentTrustReady), metav1.ConditionFalse,
			"Trust synchronization is in progress", "TrustBundleSyncing")
	}
	if err := r.patchStatus(ctx, order); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.pollInterval()}, nil
}

func (r *FulfillmentTrustReconciler) fenceDeletion(ctx context.Context, order *v1alpha1.ClusterOrder) {
	target, err := r.Targets.Resolve(ctx, order)
	if err != nil || target == nil {
		if err == nil {
			err = errors.New("target was nil")
		}
		ctrllog.FromContext(ctx).Error(err, "tenant trust cleanup could not resolve target", "clusterOrder", order.Name)
	}
	hashes := make(map[string]struct{})
	if order.Status.FulfillmentTrustBundleHash != "" {
		hashes[order.Status.FulfillmentTrustBundleHash] = struct{}{}
	}
	for _, job := range order.Status.FulfillmentTrustJobs {
		if job.ConfigVersion != "" {
			hashes[job.ConfigVersion] = struct{}{}
		}
	}
	if target != nil {
		for hash := range hashes {
			key := trustadmission.RecordKey{ClusterOrderUID: string(order.UID), TenantNamespace: r.TenantNamespace,
				ConfigMapName: trustadmission.ConfigMapName, BundleSHA256: hash}
			if err := target.Revoke(ctx, key); err != nil {
				ctrllog.FromContext(ctx).Error(err, "tenant trust record revocation failed", "clusterOrder", order.Name)
			}
		}
	}
	if job := latestActiveTrustJob(order.Status.FulfillmentTrustJobs); job != nil {
		if err := r.AAP.CancelJob(ctx, job.JobID); err != nil {
			ctrllog.FromContext(ctx).Error(err, "tenant trust job cancellation failed", "clusterOrder", order.Name)
		}
	}
}

func (r *FulfillmentTrustReconciler) failed(ctx context.Context, order *v1alpha1.ClusterOrder, reason, message string) (ctrl.Result, error) {
	order.SetStatusCondition(string(v1alpha1.ClusterOrderConditionFulfillmentTrustReady), metav1.ConditionFalse, message, reason)
	return ctrl.Result{RequeueAfter: r.pollInterval()}, r.patchStatus(ctx, order)
}

func (r *FulfillmentTrustReconciler) patchStatus(ctx context.Context, order *v1alpha1.ClusterOrder) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &v1alpha1.ClusterOrder{}
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(order), latest); err != nil {
			return err
		}
		base := latest.DeepCopy()
		latest.Status.FulfillmentTrustBundleHash = order.Status.FulfillmentTrustBundleHash
		latest.Status.FulfillmentTrustJobs = order.Status.FulfillmentTrustJobs
		if condition := apimeta.FindStatusCondition(order.Status.Conditions, string(v1alpha1.ClusterOrderConditionFulfillmentTrustReady)); condition != nil {
			apimeta.SetStatusCondition(&latest.Status.Conditions, *condition)
		}
		return r.Status().Patch(ctx, latest, client.MergeFrom(base))
	})
}

func (r *FulfillmentTrustReconciler) boundHistory(order *v1alpha1.ClusterOrder) {
	limit := r.MaxJobHistory
	if limit <= 0 {
		limit = 10
	}
	if len(order.Status.FulfillmentTrustJobs) > limit {
		order.Status.FulfillmentTrustJobs = order.Status.FulfillmentTrustJobs[len(order.Status.FulfillmentTrustJobs)-limit:]
	}
}

func (r *FulfillmentTrustReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func latestTrustJob(jobs []v1alpha1.JobStatus, hash string) *v1alpha1.JobStatus {
	for i := len(jobs) - 1; i >= 0; i-- {
		if jobs[i].ConfigVersion == hash {
			return &jobs[i]
		}
	}
	return nil
}

func latestActiveTrustJob(jobs []v1alpha1.JobStatus) *v1alpha1.JobStatus {
	for i := len(jobs) - 1; i >= 0; i-- {
		if !jobs[i].State.IsTerminal() {
			return &jobs[i]
		}
	}
	return nil
}

func (r *FulfillmentTrustReconciler) SetupWithManager(mgr mcmanager.Manager) error {
	if !r.Enabled {
		return nil
	}
	local := mgr.GetLocalManager()
	if local == nil {
		return fmt.Errorf("local manager is nil")
	}
	r.targetEvents = make(chan event.GenericEvent, 256)
	r.watchCancel = make(map[types.NamespacedName]trustWatchHandle)
	if err := local.Add(manager.RunnableFunc(func(ctx context.Context) error {
		r.watchMu.Lock()
		r.watchCtx = ctx
		r.watchMu.Unlock()
		<-ctx.Done()
		return nil
	})); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(local).
		Named("fulfillment-trust").
		For(&v1alpha1.ClusterOrder{}, builder.WithPredicates(NamespacePredicate(r.ClusterOrderNamespace))).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.mapSourceToOrders),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				name := r.SourceName
				if name == "" {
					name = trustSourceName
				}
				return obj.GetNamespace() == r.SourceNamespace && obj.GetName() == name
			}))).
		WatchesRawSource(source.Channel(r.targetEvents, &handler.EnqueueRequestForObject{})).
		Complete(r)
}

func (r *FulfillmentTrustReconciler) ensureTargetWatch(key types.NamespacedName, target FulfillmentTrustTarget) {
	watchable, ok := target.(*KubernetesTrustTarget)
	if !ok {
		return
	}
	r.watchMu.Lock()
	defer r.watchMu.Unlock()
	if r.watchCtx == nil {
		return
	}
	if existing, ok := r.watchCancel[key]; ok {
		if existing.version == watchable.CredentialVersion {
			return
		}
		existing.cancel()
	}
	ctx, cancel := context.WithCancel(r.watchCtx)
	r.watchCancel[key] = trustWatchHandle{version: watchable.CredentialVersion, cancel: cancel}
	watchable.WatchTarget(ctx, func() {
		select {
		case r.targetEvents <- event.GenericEvent{Object: &v1alpha1.ClusterOrder{ObjectMeta: metav1.ObjectMeta{
			Name: key.Name, Namespace: key.Namespace}}}:
		default:
		}
	})
}

func (r *FulfillmentTrustReconciler) stopTargetWatch(key types.NamespacedName) {
	r.watchMu.Lock()
	defer r.watchMu.Unlock()
	if handle, ok := r.watchCancel[key]; ok {
		handle.cancel()
		delete(r.watchCancel, key)
	}
}

func (r *FulfillmentTrustReconciler) mapSourceToOrders(ctx context.Context, _ client.Object) []reconcile.Request {
	orders := &v1alpha1.ClusterOrderList{}
	if err := r.List(ctx, orders, client.InNamespace(r.ClusterOrderNamespace)); err != nil {
		ctrllog.FromContext(ctx).Error(err, "list trust-enabled ClusterOrders")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(orders.Items))
	for i := range orders.Items {
		order := &orders.Items[i]
		if order.Annotations[fulfillmentTrustOptInAnnotation] == labelValueTrue &&
			order.Annotations[trustadmission.TenantAnnotation] != "" && order.Status.ClusterReference != nil {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(order)})
		}
	}
	return requests
}
