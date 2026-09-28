package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/osac-project/osac/osac-operator/api/v1alpha1"
	"github.com/osac-project/osac/osac-operator/internal/trustadmission"
	"github.com/osac-project/osac/osac-operator/pkg/aap"
)

type fakeTrustTarget struct {
	current, unsupported bool
	published, revoked   int
	events               []string
}

func (t *fakeTrustTarget) Observe(_ context.Context, _ trustadmission.ExpectedBundle) (bool, bool, error) {
	return t.current, t.unsupported, nil
}
func (t *fakeTrustTarget) Publish(_ context.Context, _ trustadmission.ExpectedBundle) error {
	t.published++
	t.events = append(t.events, "publish")
	return nil
}
func (t *fakeTrustTarget) Revoke(_ context.Context, _ trustadmission.RecordKey) error {
	t.revoked++
	t.events = append(t.events, "revoke")
	return nil
}
func (*fakeTrustTarget) CredentialID() int     { return 42 }
func (*fakeTrustTarget) CredentialRef() string { return "aap:42" }

type fakeTrustResolver struct{ target FulfillmentTrustTarget }

func (r fakeTrustResolver) Resolve(_ context.Context, _ *v1alpha1.ClusterOrder) (FulfillmentTrustTarget, error) {
	return r.target, nil
}

type fakeTrustAAP struct {
	launches      int
	status        string
	launchRequest aap.LaunchJobTemplateRequest
	events        *[]string
}

func (*fakeTrustAAP) GetTemplate(_ context.Context, _ string) (*aap.Template, error) {
	return &aap.Template{ID: 7, Type: aap.TemplateTypeJob}, nil
}
func (a *fakeTrustAAP) LaunchJobTemplate(_ context.Context, request aap.LaunchJobTemplateRequest) (*aap.LaunchJobTemplateResponse, error) {
	a.launches++
	a.launchRequest = request
	return &aap.LaunchJobTemplateResponse{JobID: 100 + a.launches}, nil
}
func (a *fakeTrustAAP) GetJob(_ context.Context, _ string) (*aap.Job, error) {
	return &aap.Job{Status: a.status}, nil
}
func (a *fakeTrustAAP) CancelJob(_ context.Context, _ string) error {
	*a.events = append(*a.events, "cancel")
	return nil
}

var _ = Describe("FulfillmentTrustReconciler", func() {
	var (
		ctx        context.Context
		order      *v1alpha1.ClusterOrder
		reconciler *FulfillmentTrustReconciler
		target     *fakeTrustTarget
		aapClient  *fakeTrustAAP
	)

	BeforeEach(func() {
		ctx = context.Background()
		order = &v1alpha1.ClusterOrder{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "trust-order-", Namespace: "default",
				Annotations: map[string]string{
					fulfillmentTrustOptInAnnotation: "true",
					trustadmission.TenantAnnotation: "tenant-a",
				},
			},
			Spec: v1alpha1.ClusterOrderSpec{TemplateID: "test.template"},
		}
		Expect(k8sClient.Create(ctx, order)).To(Succeed())
		order.Status.ClusterReference = &v1alpha1.ClusterOrderClusterReferenceType{HostedClusterName: "cluster"}
		Expect(k8sClient.Status().Update(ctx, order)).To(Succeed())
		target = &fakeTrustTarget{}
		aapClient = &fakeTrustAAP{status: "pending", events: &target.events}
		reconciler = &FulfillmentTrustReconciler{
			Client: k8sClient, APIReader: k8sClient, Enabled: true,
			ClusterOrderNamespace: "default", SourceNamespace: "default", TenantNamespace: "osac-csi",
			SourceName: "missing", AAP: aapClient, Targets: fakeTrustResolver{target}, MaxJobHistory: 2,
			PollInterval: time.Second,
		}
	})

	AfterEach(func() {
		stored := &v1alpha1.ClusterOrder{}
		if k8sClient.Get(ctx, client.ObjectKeyFromObject(order), stored) == nil {
			stored.Finalizers = nil
			Expect(k8sClient.Update(ctx, stored)).To(Succeed())
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, stored))).To(Succeed())
		}
	})

	reconcile := func() {
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(order)})
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
	}
	getOrder := func() *v1alpha1.ClusterOrder {
		stored := &v1alpha1.ClusterOrder{}
		ExpectWithOffset(1, k8sClient.Get(ctx, client.ObjectKeyFromObject(order), stored)).To(Succeed())
		return stored
	}
	addBundle := func() []byte {
		bundle := testTrustPEM()
		configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{GenerateName: "trust-source-", Namespace: "default"},
			Data: map[string]string{trustadmission.BundleDataKey: string(bundle)}}
		ExpectWithOffset(1, k8sClient.Create(ctx, configMap)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, configMap)).To(Succeed()) })
		reconciler.SourceName = configMap.Name
		return bundle
	}

	It("does no work while disabled", func() {
		reconciler.Enabled = false
		reconcile()
		Expect(getOrder().Status.Conditions).To(BeEmpty())
		Expect(aapClient.launches).To(BeZero())
		Expect(target.published).To(BeZero())
	})

	It("reports a missing source without launching", func() {
		reconcile()
		condition := getOrder().Status.Conditions[0]
		Expect(condition.Reason).To(Equal("TrustBundleUnavailable"))
		Expect(aapClient.launches).To(BeZero())
	})

	It("reports missing protected credentials without launching or writing", func() {
		addBundle()
		reconciler.Targets = fakeTrustResolver{}
		reconcile()
		Expect(getOrder().Status.Conditions[0].Reason).To(Equal("KubeconfigNotAvailable"))
		Expect(aapClient.launches).To(BeZero())
		Expect(target.published).To(BeZero())
	})

	It("revokes and cancels an in-flight job when the source becomes invalid", func() {
		addBundle()
		reconcile()
		configMap := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: reconciler.SourceName}, configMap)).To(Succeed())
		configMap.Data[trustadmission.BundleDataKey] = "invalid PEM"
		Expect(k8sClient.Update(ctx, configMap)).To(Succeed())

		reconcile()
		stored := getOrder()
		Expect(stored.Status.Conditions[0].Reason).To(Equal("TrustBundleUnavailable"))
		Expect(stored.Status.FulfillmentTrustJobs[0].State).To(Equal(v1alpha1.JobStateCanceled))
		Expect(strings.Join(target.events, ",")).To(ContainSubstring("revoke,cancel"))
		Expect(aapClient.launches).To(Equal(1))
	})

	It("revokes an old hash before launching a rotated bundle", func() {
		addBundle()
		reconcile()
		configMap := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: reconciler.SourceName}, configMap)).To(Succeed())
		configMap.Data[trustadmission.BundleDataKey] = string(testTrustPEM())
		Expect(k8sClient.Update(ctx, configMap)).To(Succeed())

		reconcile()
		Expect(aapClient.launches).To(Equal(1))
		Expect(getOrder().Status.FulfillmentTrustJobs[0].State).To(Equal(v1alpha1.JobStateCanceled))
		Expect(strings.Join(target.events, ",")).To(ContainSubstring("revoke,cancel"))
		reconcile()
		Expect(aapClient.launches).To(Equal(2))
		Expect(getOrder().Status.FulfillmentTrustJobs).To(HaveLen(2))
	})

	It("tracks one job, verifies the target, and relaunches on same-hash drift", func() {
		bundle := addBundle()
		reconcile()
		stored := getOrder()
		Expect(stored.Status.FulfillmentTrustJobs).To(HaveLen(1))
		Expect(stored.Status.FulfillmentTrustBundleHash).To(BeEmpty())
		Expect(aapClient.launches).To(Equal(1))
		Expect(aapClient.launchRequest.CredentialIDs).To(Equal([]int{42}))
		vars := aapClient.launchRequest.ExtraVars["osac_job_vars"].(map[string]any)
		Expect(vars).NotTo(HaveKey("admin_kubeconfig"))
		Expect(vars).NotTo(HaveKey("kubeconfig"))
		Expect(vars["fulfillment_trust"].(map[string]string)["bundle_pem"]).To(Equal(string(bundle)))

		reconcile()
		Expect(aapClient.launches).To(Equal(1))
		Expect(getOrder().Status.FulfillmentTrustBundleHash).To(BeEmpty())
		aapClient.status = "successful"
		reconcile()
		Expect(getOrder().Status.FulfillmentTrustBundleHash).To(BeEmpty())
		target.current = true
		reconcile()
		Expect(getOrder().IsStatusConditionTrue(string(v1alpha1.ClusterOrderConditionFulfillmentTrustReady))).To(BeTrue())
		Expect(getOrder().Status.FulfillmentTrustBundleHash).NotTo(BeEmpty())
		Expect(aapClient.launches).To(Equal(1))

		target.current = false
		reconcile()
		Expect(aapClient.launches).To(Equal(2))
		Expect(getOrder().Status.FulfillmentTrustJobs).To(HaveLen(2))
	})

	It("reports an unsupported CSI controller without launching", func() {
		addBundle()
		target.unsupported = true
		reconcile()
		Expect(getOrder().Status.Conditions[0].Reason).To(Equal("CSIClientUpgradeRequired"))
		Expect(aapClient.launches).To(BeZero())
	})

	It("revokes the expected bundle before canceling on deletion", func() {
		addBundle()
		reconcile()
		stored := getOrder()
		stored.Finalizers = []string{"test.osac.openshift.io/finalizer"}
		Expect(k8sClient.Update(ctx, stored)).To(Succeed())
		Expect(k8sClient.Delete(ctx, stored)).To(Succeed())
		reconcile()
		Expect(target.events).To(ContainElements("revoke", "cancel"))
		Expect(strings.Join(target.events, ",")).To(ContainSubstring("revoke,cancel"))
		Expect(aapClient.launches).To(Equal(1))
	})
})

var _ = Describe("KubernetesTrustTarget", func() {
	It("uses an observer identity that cannot write or read Secrets", func() {
		ctx := context.Background()
		serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{GenerateName: "trust-observer-", Namespace: "default"}}
		Expect(k8sClient.Create(ctx, serviceAccount)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, serviceAccount))).To(Succeed()) })
		role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{GenerateName: "trust-observer-", Namespace: "default"},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{trustadmission.ConfigMapName}, Verbs: []string{"get", "list", "watch"}},
				{APIGroups: []string{"apps"}, Resources: []string{"deployments", "replicasets"}, Verbs: []string{"get", "list", "watch"}},
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
			}}
		Expect(k8sClient.Create(ctx, role)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, role))).To(Succeed()) })
		binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{GenerateName: "trust-observer-", Namespace: "default"},
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: serviceAccount.Name, Namespace: "default"}}}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, binding))).To(Succeed()) })
		configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: trustadmission.ConfigMapName, Namespace: "default"}}
		Expect(k8sClient.Create(ctx, configMap)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, configMap))).To(Succeed()) })

		observerConfig := rest.CopyConfig(cfg)
		observerConfig.Impersonate.UserName = "system:serviceaccount:default:" + serviceAccount.Name
		observerConfig.Impersonate.Groups = []string{"system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated"}
		observer, err := client.New(observerConfig, client.Options{Scheme: k8sClient.Scheme()})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() error {
			return observer.Get(ctx, client.ObjectKeyFromObject(configMap), &corev1.ConfigMap{})
		}).Should(Succeed())
		Expect(apierrors.IsForbidden(observer.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "unauthorized", Namespace: "default"}}))).To(BeTrue())
		Expect(apierrors.IsForbidden(observer.Get(ctx, client.ObjectKey{Namespace: "default", Name: "private"}, &corev1.Secret{}))).To(BeTrue())
	})

	It("detects legacy CSI, stale rollout, and an old ready Pod", func() {
		ctx := context.Background()
		bundle := testTrustPEM()
		record := trustadmission.ExpectedBundle{
			Key: trustadmission.RecordKey{ClusterOrderUID: "order-uid", TenantNamespace: "osac-csi",
				ConfigMapName: trustadmission.ConfigMapName, BundleSHA256: "hash"},
			Tenant: "tenant-a", OwnerReference: "order-uid", BundlePEM: bundle,
		}
		configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: trustadmission.ConfigMapName, Namespace: "osac-csi",
			Annotations: map[string]string{trustadmission.TenantAnnotation: record.Tenant,
				trustadmission.OwnerReferenceAnnotation: record.OwnerReference,
				trustadmission.BundleHashAnnotation:     record.Key.BundleSHA256}},
			Data: map[string]string{trustadmission.BundleDataKey: string(bundle)}}
		deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "csi", Namespace: "osac-csi", UID: types.UID("dep-uid"), Generation: 2,
			Labels: map[string]string{trustCSINameLabel: "csi-driver", trustCSIComponentLabel: "controller"}},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{trustadmission.BundleHashAnnotation: "hash"}}}},
			Status: appsv1.DeploymentStatus{ObservedGeneration: 2, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}}
		one := int32(1)
		deployment.Spec.Replicas = &one
		observer := fake.NewClientBuilder().WithScheme(k8sClient.Scheme()).WithObjects(configMap, deployment).Build()
		target := &KubernetesTrustTarget{Observer: observer, Namespace: "osac-csi"}
		current, unsupported, err := target.Observe(ctx, record)
		Expect(err).NotTo(HaveOccurred())
		Expect(current).To(BeFalse())
		Expect(unsupported).To(BeTrue())

		deployment.Labels[trustadmission.TrustClientLabel] = "true"
		Expect(observer.Update(ctx, deployment)).To(Succeed())
		current, unsupported, err = target.Observe(ctx, record)
		Expect(err).NotTo(HaveOccurred())
		Expect(current).To(BeTrue())
		Expect(unsupported).To(BeFalse())

		oldRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: "osac-csi", UID: types.UID("rs-uid"),
			OwnerReferences: []metav1.OwnerReference{{UID: deployment.UID}}},
			Spec: appsv1.ReplicaSetSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{trustadmission.BundleHashAnnotation: "old"}}}}}
		Expect(observer.Create(ctx, oldRS)).To(Succeed())
		oldPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: "osac-csi",
			OwnerReferences: []metav1.OwnerReference{{UID: oldRS.UID}}},
			Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
		Expect(observer.Create(ctx, oldPod)).To(Succeed())
		current, _, err = target.Observe(ctx, record)
		Expect(err).NotTo(HaveOccurred())
		Expect(current).To(BeFalse())
	})
})

var _ = Describe("SecretTrustTargetResolver", func() {
	It("accepts distinct verified service-account credentials scoped to the order", func() {
		ctx := context.Background()
		order := &v1alpha1.ClusterOrder{ObjectMeta: metav1.ObjectMeta{UID: types.UID("order-uid"),
			Annotations: map[string]string{trustadmission.TenantAnnotation: "tenant-a"}}}
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: trustCredentialsPrefix + string(order.UID), Namespace: "default",
			Annotations: map[string]string{trustadmission.OwnerReferenceAnnotation: string(order.UID),
				trustadmission.TenantAnnotation: "tenant-a"}},
			Data: map[string][]byte{
				trustObserverKubeconfigKey:  testTrustKubeconfig("observer-token"),
				trustPublisherKubeconfigKey: testTrustKubeconfig("publisher-token"),
				trustAAPCredentialIDKey:     []byte("42"),
				trustAAPCredentialRefKey:    []byte("aap:42"),
			}}
		management := fake.NewClientBuilder().WithScheme(k8sClient.Scheme()).WithObjects(secret).Build()
		resolver := &SecretTrustTargetResolver{Management: management, Namespace: "default", TenantNamespace: "osac-csi"}
		target, err := resolver.Resolve(ctx, order)
		Expect(err).NotTo(HaveOccurred())
		Expect(target.CredentialID()).To(Equal(42))
		Expect(target.CredentialRef()).To(Equal("aap:42"))

		secret.Data[trustPublisherKubeconfigKey] = secret.Data[trustObserverKubeconfigKey]
		Expect(management.Update(ctx, secret)).To(Succeed())
		_, err = resolver.Resolve(ctx, order)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("observer-token"))
		secret.Annotations[trustadmission.TenantAnnotation] = "another-tenant"
		Expect(management.Update(ctx, secret)).To(Succeed())
		_, err = resolver.Resolve(ctx, order)
		Expect(err).To(HaveOccurred())
	})
})

func testTrustKubeconfig(token string) []byte {
	config := clientcmdapi.NewConfig()
	config.Clusters["tenant"] = &clientcmdapi.Cluster{Server: "https://tenant.example.invalid",
		CertificateAuthorityData: testTrustPEM()}
	config.AuthInfos["service-account"] = &clientcmdapi.AuthInfo{Token: token}
	config.Contexts["tenant"] = &clientcmdapi.Context{Cluster: "tenant", AuthInfo: "service-account"}
	config.CurrentContext = "tenant"
	data, err := clientcmd.Write(*config)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return data
}

func testTrustPEM() []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test trust CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
