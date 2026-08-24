/*
Copyright (c) 2026 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package grpcserver

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	privatev1 "github.com/osac-project/osac/fulfillment-service/internal/api/osac/private/v1"
	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	"github.com/osac-project/osac/fulfillment-service/internal/references"
)

func TestRegisterReferenceLookups(t *testing.T) {
	validator := newTestReferenceValidator(t)

	t.Run("registers SecretLocalReference for private and public APIs", func(t *testing.T) {
		for _, name := range []protoreflect.FullName{
			"osac.private.v1.SecretLocalReference",
			"osac.public.v1.SecretLocalReference",
		} {
			if !validator.HasLookup(name) {
				t.Errorf("missing lookup for %s", name)
			}
		}
	})

	t.Run("registers every reference type used in Create or Update requests", func(t *testing.T) {
		var missing []string
		for _, name := range createOrUpdateReferenceTypes(t) {
			if !validator.HasLookup(name) {
				missing = append(missing, string(name))
			}
		}
		slices.Sort(missing)
		if len(missing) > 0 {
			t.Errorf("no lookup registered for Create/Update reference types:\n  %s",
				strings.Join(missing, "\n  "))
		}
	})

	t.Run("interceptor does not reject identity provider client_secret_secret as unregistered", func(t *testing.T) {
		request := privatev1.IdentityProvidersCreateRequest_builder{
			Object: privatev1.IdentityProvider_builder{
				Spec: privatev1.IdentityProviderSpec_builder{
					Oidc: privatev1.OidcConfig_builder{
						ClientSecretSecret: privatev1.SecretLocalReference_builder{
							Id: "secret-id",
						}.Build(),
					}.Build(),
				}.Build(),
			}.Build(),
		}.Build()

		_, err := validator.UnaryServer(
			context.Background(),
			request,
			&grpc.UnaryServerInfo{FullMethod: "/osac.private.v1.IdentityProviders/Create"},
			func(context.Context, any) (any, error) { return "ok", nil },
		)
		if err == nil {
			return
		}
		st, _ := grpcstatus.FromError(err)
		if strings.Contains(st.Message(), "no lookup registered") {
			t.Fatalf("SecretLocalReference is not registered with the interceptor: %v", err)
		}
	})
}

func newTestReferenceValidator(t *testing.T) *references.ReferenceValidator {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tenancy, err := auth.NewGuestTenancyLogic().SetLogger(logger).Build()
	if err != nil {
		t.Fatalf("failed to create guest tenancy logic: %v", err)
	}
	validator, err := references.NewReferenceValidator().SetLogger(logger).Build()
	if err != nil {
		t.Fatalf("failed to create reference validator: %v", err)
	}
	if err := registerReferenceLookups(validator, logger, tenancy, prometheus.NewRegistry()); err != nil {
		t.Fatalf("failed to register reference lookups: %v", err)
	}
	return validator
}

func createOrUpdateReferenceTypes(t *testing.T) []protoreflect.FullName {
	t.Helper()
	seen := map[protoreflect.FullName]struct{}{}
	refs := map[protoreflect.FullName]struct{}{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		pkg := string(fd.Package())
		if pkg != "osac.private.v1" && pkg != "osac.public.v1" {
			return true
		}
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			methods := services.Get(i).Methods()
			for j := 0; j < methods.Len(); j++ {
				method := methods.Get(j)
				name := string(method.Name())
				if name != "Create" && name != "Update" {
					continue
				}
				collectReferenceTypes(method.Input(), seen, refs)
			}
		}
		return true
	})
	result := make([]protoreflect.FullName, 0, len(refs))
	for name := range refs {
		result = append(result, name)
	}
	slices.Sort(result)
	return result
}

func collectReferenceTypes(
	md protoreflect.MessageDescriptor,
	seen map[protoreflect.FullName]struct{},
	refs map[protoreflect.FullName]struct{},
) {
	if md == nil {
		return
	}
	name := md.FullName()
	if _, ok := seen[name]; ok {
		return
	}
	seen[name] = struct{}{}

	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.Kind() != protoreflect.MessageKind || fd.IsMap() {
			continue
		}
		msg := fd.Message()
		if strings.HasSuffix(string(msg.FullName()), "Reference") {
			refs[msg.FullName()] = struct{}{}
			continue
		}
		collectReferenceTypes(msg, seen, refs)
	}
}
