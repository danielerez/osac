/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
*/

package servers

import (
	"context"
	"errors"
	"github.com/osac-project/osac/fulfillment-service/internal/database/dao"
	"github.com/osac-project/osac/fulfillment-service/internal/serviceaccounts"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/osac-project/osac/fulfillment-service/internal/controllers/finalizers"
	"github.com/osac-project/osac/fulfillment-service/internal/database"

	"github.com/prometheus/client_golang/prometheus"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	"github.com/osac-project/osac/fulfillment-service/internal/idp"
	privatev1 "github.com/osac-project/osac/proto/gen/osac/private/v1"
)

// PrivateServiceAccountsServerBuilder is a builder for creating instances of PrivateServiceAccountsServer.
type PrivateServiceAccountsServerBuilder struct {
	logger            *slog.Logger
	attributionLogic  auth.AttributionLogic
	tenancyLogic      auth.TenancyLogic
	metricsRegisterer prometheus.Registerer
	idpClient         idp.ClientInterface
	filterDesc        protoreflect.MessageDescriptor
}

var _ privatev1.ServiceAccountsServer = (*PrivateServiceAccountsServer)(nil)

const maxAssignableServiceAccountRoles = 4

// PrivateServiceAccountsServer implements the private service accounts gRPC service.
type PrivateServiceAccountsServer struct {
	privatev1.UnimplementedServiceAccountsServer

	logger    *slog.Logger
	generic   *GenericServer[*privatev1.ServiceAccount]
	idpClient idp.ClientInterface
	roles     *dao.GenericDAO[*privatev1.Role]
}

// NewPrivateServiceAccountsServer creates a new builder for the private service accounts server.
func NewPrivateServiceAccountsServer() *PrivateServiceAccountsServerBuilder {
	return &PrivateServiceAccountsServerBuilder{}
}

// SetLogger sets the logger to use. This is mandatory.
func (b *PrivateServiceAccountsServerBuilder) SetLogger(value *slog.Logger) *PrivateServiceAccountsServerBuilder {
	b.logger = value
	return b
}

// SetAttributionLogic sets the attribution logic to use. This is optional.
func (b *PrivateServiceAccountsServerBuilder) SetAttributionLogic(value auth.AttributionLogic) *PrivateServiceAccountsServerBuilder {
	b.attributionLogic = value
	return b
}

// SetTenancyLogic sets the tenancy logic to use. This is mandatory.
func (b *PrivateServiceAccountsServerBuilder) SetTenancyLogic(value auth.TenancyLogic) *PrivateServiceAccountsServerBuilder {
	b.tenancyLogic = value
	return b
}

// SetMetricsRegisterer sets the Prometheus registerer used to register the metrics for the underlying database
// access objects. This is optional. If not set, no metrics will be recorded.
func (b *PrivateServiceAccountsServerBuilder) SetMetricsRegisterer(value prometheus.Registerer) *PrivateServiceAccountsServerBuilder {
	b.metricsRegisterer = value
	return b
}

// SetFilterDesc sets the protobuf message descriptor used to validate and translate CEL filter
// expressions. This is optional. When unset, the descriptor of this server's own private message type is used.
func (b *PrivateServiceAccountsServerBuilder) SetFilterDesc(value protoreflect.MessageDescriptor) *PrivateServiceAccountsServerBuilder {
	b.filterDesc = value
	return b
}

func (b *PrivateServiceAccountsServerBuilder) SetIdpClient(value idp.ClientInterface) *PrivateServiceAccountsServerBuilder {
	b.idpClient = value
	return b
}

// Build creates the private service accounts server from the builder configuration.
func (b *PrivateServiceAccountsServerBuilder) Build() (result *PrivateServiceAccountsServer, err error) {
	if b.logger == nil {
		err = errors.New("logger is mandatory")
		return
	}
	if b.idpClient == nil {
		return nil, errors.New("IDP client is mandatory")
	}
	if b.tenancyLogic == nil {
		err = errors.New("tenancy logic is mandatory")
		return
	}

	generic, err := NewGenericServer[*privatev1.ServiceAccount]().
		SetLogger(b.logger).
		SetService(privatev1.ServiceAccounts_ServiceDesc.ServiceName).
		SetAttributionLogic(b.attributionLogic).
		SetTenancyLogic(b.tenancyLogic).
		SetMetricsRegisterer(b.metricsRegisterer).
		SetFilterDesc(b.filterDesc).
		Build()
	if err != nil {
		return
	}

	roles, err := dao.NewGenericDAO[*privatev1.Role]().SetLogger(b.logger).SetTenancyLogic(b.tenancyLogic).Build()
	if err != nil {
		return nil, err
	}
	result = &PrivateServiceAccountsServer{
		idpClient: b.idpClient, roles: roles,
		logger:  b.logger,
		generic: generic,
	}
	return
}

func (s *PrivateServiceAccountsServer) List(ctx context.Context,
	request *privatev1.ServiceAccountsListRequest) (response *privatev1.ServiceAccountsListResponse, err error) {
	err = s.generic.List(ctx, request, &response)
	return
}

func (s *PrivateServiceAccountsServer) Get(ctx context.Context,
	request *privatev1.ServiceAccountsGetRequest) (response *privatev1.ServiceAccountsGetResponse, err error) {
	err = s.generic.Get(ctx, request, &response)
	return
}

func (s *PrivateServiceAccountsServer) Create(ctx context.Context,
	request *privatev1.ServiceAccountsCreateRequest) (response *privatev1.ServiceAccountsCreateResponse, err error) {
	tx, err := database.TxFromContext(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.ReportError(&err)
	if request.GetObject().GetId() != "" {
		return nil, status.Error(codes.InvalidArgument, "service-account ID is assigned by the server")
	}
	err = s.generic.CreateWithCandidatePreparation(ctx, request, &response, s.prepareCreate)
	if err != nil || isDryRun(ctx) {
		return
	}
	account := response.GetObject()
	tenant := account.GetMetadata().GetTenant()
	clientID := serviceaccounts.ClientID(tenant, account.GetId())
	s.logger.InfoContext(ctx, "Creating service-account client", "tenant", tenant, "account_id", account.GetId(), "client_id", clientID)
	clientUUID, secret, setupErr := s.idpClient.CreateServiceAccountClient(ctx, clientID, tenant)
	defer func() {
		if err != nil {
			response = nil
			if clientUUID != "" {
				s.compensateClient(ctx, clientUUID, clientID)
			}
		}
	}()
	if setupErr != nil {
		return nil, status.Error(codes.Unavailable, "failed to configure service-account client")
	}
	if _, parseErr := uuid.Parse(clientUUID); parseErr != nil || secret == "" {
		return nil, status.Error(codes.Unavailable, "invalid service-account client setup result")
	}
	account.SetStatus(privatev1.ServiceAccountStatus_builder{ClientId: clientID, KeycloakClientUuid: clientUUID}.Build())
	updated, updateErr := s.generic.dao.Update().SetObject(account).Do(ctx)
	if updateErr != nil {
		return nil, ConvertDAOErrorToGRPC(updateErr, "update", account.GetId())
	}
	response.SetObject(updated.GetObject())
	response.SetClientSecret(secret)
	return
}

func (s *PrivateServiceAccountsServer) prepareCreate(ctx context.Context, _, account *privatev1.ServiceAccount) error {
	account.ClearStatus()
	metadata := account.GetMetadata()
	metadata.SetFinalizers([]string{finalizers.Controller})
	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations["osac.openshift.io/tenant"] = metadata.GetTenant()
	metadata.SetAnnotations(annotations)
	return s.validateRoles(ctx, account)
}

func (s *PrivateServiceAccountsServer) compensateClient(ctx context.Context, clientUUID, clientID string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.idpClient.DisableServiceAccountClient(cleanupCtx, clientUUID); err != nil {
		s.logger.ErrorContext(cleanupCtx, "Failed to disable service-account client during compensation", "client_id", clientID)
	}
	if err := s.idpClient.DeleteServiceAccountClient(cleanupCtx, clientUUID); err != nil {
		s.logger.ErrorContext(cleanupCtx, "Failed to delete service-account client during compensation", "client_id", clientID)
	}
}

func (s *PrivateServiceAccountsServer) Update(ctx context.Context,
	request *privatev1.ServiceAccountsUpdateRequest) (response *privatev1.ServiceAccountsUpdateResponse, err error) {
	return s.update(ctx, request)
}

func (s *PrivateServiceAccountsServer) Delete(ctx context.Context,
	request *privatev1.ServiceAccountsDeleteRequest) (response *privatev1.ServiceAccountsDeleteResponse, err error) {
	err = s.generic.Delete(ctx, request, &response)
	return
}

func (s *PrivateServiceAccountsServer) Signal(ctx context.Context,
	request *privatev1.ServiceAccountsSignalRequest) (response *privatev1.ServiceAccountsSignalResponse, err error) {
	err = s.generic.Signal(ctx, request, &response)
	return
}

func (s *PrivateServiceAccountsServer) RegenerateSecret(context.Context, *privatev1.ServiceAccountsRegenerateSecretRequest) (*privatev1.ServiceAccountsRegenerateSecretResponse, error) {
	return nil, status.Error(codes.Unimplemented, "service-account secret regeneration is not implemented")
}

func (s *PrivateServiceAccountsServer) update(ctx context.Context, request *privatev1.ServiceAccountsUpdateRequest) (*privatev1.ServiceAccountsUpdateResponse, error) {
	if request.GetObject().GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "object identifier is mandatory")
	}
	request = proto.Clone(request).(*privatev1.ServiceAccountsUpdateRequest)
	mask := request.GetUpdateMask()
	if mask == nil {
		mask = &fieldmaskpb.FieldMask{Paths: []string{"metadata.display_name", "metadata.description", "metadata.labels", "spec.roles"}}
		if request.GetObject().GetMetadata().GetName() != "" {
			mask.Paths = append(mask.Paths, "metadata.name")
		}
		request.SetUpdateMask(mask)
	}
	for _, path := range mask.GetPaths() {
		switch path {
		case "metadata.name", "metadata.display_name", "metadata.description", "metadata.labels", "spec", "spec.roles":
		case "metadata.finalizers":
			if isPublicAPIView(ctx) {
				return nil, status.Error(codes.InvalidArgument, "finalizers are server-owned")
			}
		default:
			return nil, status.Errorf(codes.InvalidArgument, "field %q is not mutable", path)
		}
	}
	var response *privatev1.ServiceAccountsUpdateResponse
	prepare := s.prepareUpdate
	// Cleanup must remain possible when a previously assigned catalog role no longer exists.
	if len(mask.GetPaths()) == 1 && mask.GetPaths()[0] == "metadata.finalizers" {
		prepare = nil
	}
	err := s.generic.UpdateWithCandidatePreparation(ctx, request, &response, prepare)
	return response, err
}

func (s *PrivateServiceAccountsServer) prepareUpdate(ctx context.Context, current, candidate *privatev1.ServiceAccount) error {
	if current.GetMetadata().GetName() != candidate.GetMetadata().GetName() {
		return status.Error(codes.InvalidArgument, "service-account name is immutable")
	}
	return s.validateRoles(ctx, candidate)
}

func (s *PrivateServiceAccountsServer) validateRoles(ctx context.Context, account *privatev1.ServiceAccount) error {
	roles := account.GetSpec().GetRoles()
	if len(roles) > maxAssignableServiceAccountRoles {
		return status.Error(codes.InvalidArgument, "at most four service-account roles may be assigned")
	}
	for _, ref := range roles {
		if ref.GetId() == "" {
			return status.Error(codes.InvalidArgument, "unsupported service-account role")
		}
		result, err := s.roles.Get().SetId(ref.GetId()).Do(ctx)
		if err != nil {
			if _, ok := errors.AsType[*dao.ErrNotFound](err); ok {
				return status.Error(codes.InvalidArgument, "unsupported service-account role")
			}
			return err
		}
		role := result.GetObject()
		if !serviceaccounts.IsAssignableRole(role.GetMetadata().GetName()) || role.GetMetadata().GetTenant() != auth.SharedTenant {
			return status.Error(codes.InvalidArgument, "unsupported service-account role")
		}
	}
	slices.SortFunc(roles, func(a, b *privatev1.RoleReference) int { return strings.Compare(a.GetId(), b.GetId()) })
	return nil
}
