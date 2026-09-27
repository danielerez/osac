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

package trustadmission_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2" //nolint:revive,staticcheck
	. "github.com/onsi/gomega"    //nolint:revive,staticcheck
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/osac-project/osac/osac-operator/internal/trustadmission"
)

var _ = Describe("KubernetesStore", func() {
	var (
		now    time.Time
		store  trustadmission.Store
		record trustadmission.ExpectedBundle
	)

	BeforeEach(func() {
		now = time.Date(2026, time.September, 27, 12, 0, 0, 0, time.UTC)
		clientset := fake.NewSimpleClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:      trustadmission.ExpectedBundleStoreName,
			Namespace: tenantNamespace,
		}})
		var err error
		store, err = trustadmission.NewKubernetesStore(clientset.CoreV1(), tenantNamespace)
		Expect(err).NotTo(HaveOccurred())
		record = expectedBundle(certificatePEM(), now.Add(time.Hour))
	})

	It("persists an active record for a restarted admission service", func() {
		Expect(store.Publish(record)).To(Succeed())

		Expect(store.AuthorizeConfigMap(configMapFor(record), now)).To(Succeed())
	})

	It("removes persisted records atomically when revoked", func() {
		Expect(store.Publish(record)).To(Succeed())
		Expect(store.Revoke(record.Key)).To(Succeed())

		Expect(store.AuthorizeConfigMap(configMapFor(record), now)).NotTo(Succeed())
	})

	It("fails closed when the protected store is absent", func() {
		clientset := fake.NewSimpleClientset()
		missingStore, err := trustadmission.NewKubernetesStore(clientset.CoreV1(), tenantNamespace)
		Expect(err).NotTo(HaveOccurred())

		Expect(missingStore.AuthorizeConfigMap(configMapFor(record), now)).NotTo(Succeed())
	})
})
