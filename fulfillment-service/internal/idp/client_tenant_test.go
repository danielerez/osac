/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Keycloak tenant client", func() {
	var (
		ctx    context.Context
		server *httptest.Server
		client *Client
		mux    *http.ServeMux
	)

	BeforeEach(func() {
		ctx = context.Background()
		mux = http.NewServeMux()
		server = httptest.NewServer(mux)

		var err error
		client, err = NewClient().
			SetLogger(logger).
			SetBaseURL(server.URL).
			SetTokenSource(&staticTokenSource{}).
			Build()
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		server.Close()
	})

	Describe("DeleteTenant", func() {
		It("returns an error while the organization is still visible after deletion", func() {
			var deleteCalled atomic.Bool
			mux.HandleFunc("GET /admin/realms/osac/users", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode([]keycloakUser{})
			})
			mux.HandleFunc("GET /admin/realms/osac/organizations", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode([]keycloakOrganization{{ID: "org-123", Name: "shared"}})
			})
			mux.HandleFunc("DELETE /admin/realms/osac/organizations/org-123", func(w http.ResponseWriter, _ *http.Request) {
				deleteCalled.Store(true)
				w.WriteHeader(http.StatusNoContent)
			})

			err := client.DeleteTenant(ctx, "shared")

			Expect(deleteCalled.Load()).To(BeTrue())
			Expect(err).To(MatchError(ContainSubstring("still exists after deletion")))
		})

		It("succeeds once the organization is absent after deletion", func() {
			var organizationDeleted atomic.Bool
			mux.HandleFunc("GET /admin/realms/osac/users", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode([]keycloakUser{})
			})
			mux.HandleFunc("GET /admin/realms/osac/organizations", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if organizationDeleted.Load() {
					json.NewEncoder(w).Encode([]keycloakOrganization{})
					return
				}
				json.NewEncoder(w).Encode([]keycloakOrganization{{ID: "org-123", Name: "shared"}})
			})
			mux.HandleFunc("DELETE /admin/realms/osac/organizations/org-123", func(w http.ResponseWriter, _ *http.Request) {
				organizationDeleted.Store(true)
				w.WriteHeader(http.StatusNoContent)
			})

			err := client.DeleteTenant(ctx, "shared")

			Expect(err).ToNot(HaveOccurred())
		})
	})
})
