/*
Copyright (c) 2026 Red Hat Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0
*/

package servers

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/osac-project/osac/fulfillment-service/internal/auth"
	"github.com/osac-project/osac/fulfillment-service/internal/collections"
	"github.com/osac-project/osac/fulfillment-service/internal/database"
	"github.com/osac-project/osac/fulfillment-service/internal/idp"
	"github.com/osac-project/osac/fulfillment-service/internal/logging"
	testutils "github.com/osac-project/osac/fulfillment-service/internal/testing"
	publicv1 "github.com/osac-project/osac/proto/gen/osac/public/v1"
)

var _ = Describe("Service account creation", func() {
	const clientUUID = "d3c4e3db-95b8-481d-8b5c-963da477da12"
	const credential = "test-only-credential-marker"
	var public *ServiceAccountsServer
	var idpClient *idp.MockClientInterface
	var request *publicv1.ServiceAccountsCreateRequest
	var create func(context.Context, *publicv1.ServiceAccountsCreateRequest) (*publicv1.ServiceAccountsCreateResponse, error)
	var caller context.Context
	BeforeEach(func() {
		Expect(suiteTx.End(ctx)).To(Succeed())
		suiteTx = nil
		caller = auth.ContextWithSubject(context.Background(), &auth.Subject{User: "admin", Tenants: collections.NewSet(testTenant)})
		tenancyLogic, err := auth.NewDefaultTenancyLogic().SetLogger(logger).Build()
		Expect(err).ToNot(HaveOccurred())
		idpClient = idp.NewMockClientInterface(ctrl)
		public, err = NewServiceAccountsServer().SetLogger(logger).SetAttributionLogic(attribution).
			SetTenancyLogic(tenancyLogic).SetIdpClient(idpClient).Build()
		Expect(err).ToNot(HaveOccurred())
		txInterceptor, err := database.NewTxInterceptor().SetLogger(logger).SetManager(tm).Build()
		Expect(err).ToNot(HaveOccurred())
		create = func(ctx context.Context, req *publicv1.ServiceAccountsCreateRequest) (*publicv1.ServiceAccountsCreateResponse, error) {
			response, err := txInterceptor.UnaryServer(ctx, req, &grpc.UnaryServerInfo{FullMethod: publicv1.ServiceAccounts_Create_FullMethodName},
				func(ctx context.Context, req any) (any, error) {
					return public.Create(ctx, req.(*publicv1.ServiceAccountsCreateRequest))
				})
			if response == nil {
				return nil, err
			}
			return response.(*publicv1.ServiceAccountsCreateResponse), err
		}
		request = publicv1.ServiceAccountsCreateRequest_builder{Object: publicv1.ServiceAccount_builder{
			Metadata: publicv1.Metadata_builder{Name: "robot", DisplayName: "Build robot"}.Build(),
		}.Build()}.Build()
	})
	It("reserves a generated identity and returns a transient initial credential", func() {
		var assignedClientID string
		idpClient.EXPECT().CreateServiceAccountClient(gomock.Any(), gomock.Any(), testTenant).
			DoAndReturn(func(ctx context.Context, clientID, tenant string) (string, string, error) {
				assignedClientID = clientID
				id := strings.TrimPrefix(clientID, "osac-sa-"+testTenant+"-")
				_, err := uuid.Parse(id)
				Expect(err).ToNot(HaveOccurred())
				tx, err := database.TxFromContext(ctx)
				Expect(err).ToNot(HaveOccurred())
				var finalizers []string
				Expect(tx.QueryRow(ctx, `select finalizers from service_accounts where id=$1 and tenant=$2`, id, tenant).Scan(&finalizers)).To(Succeed())
				Expect(finalizers).To(ContainElement("fulfillment-controller"))
				return clientUUID, credential, nil
			})
		request.GetObject().SetStatus(publicv1.ServiceAccountStatus_builder{ClientId: "forged"}.Build())
		request.GetObject().GetMetadata().SetAnnotations(map[string]string{"osac.openshift.io/tenant": "forged"})
		response, err := create(caller, request)
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetClientSecret()).To(Equal(credential))
		Expect(response.GetObject().GetStatus().GetClientId()).To(Equal(assignedClientID))
		Expect(response.GetObject().GetMetadata().GetDisplayName()).To(Equal("Build robot"))
		Expect(response.GetObject().GetMetadata().GetTenant()).To(Equal(testTenant))
		Expect(response.GetObject().GetMetadata().GetAnnotations()).To(HaveKeyWithValue("osac.openshift.io/tenant", testTenant))
		var data, target string
		Expect(testPool.QueryRow(ctx, `select data::text, data->'status'->>'keycloak_client_uuid' from service_accounts where id=$1`, response.GetObject().GetId()).Scan(&data, &target)).To(Succeed())
		Expect(target).To(Equal(clientUUID))
		Expect(strings.Contains(data, credential)).To(BeFalse())
		var count int
		Expect(testPool.QueryRow(ctx, `select count(*) from changes where "table"='service_accounts' and data::text like $1`, "%"+credential+"%").Scan(&count)).To(Succeed())
		Expect(count).To(BeZero())
		Expect(request.GetObject().GetStatus().GetClientId()).To(Equal("forged"), "input must remain unmodified")
	})
	It("validates a dry run without creating a row, client, or secret", func() {
		dry := metadata.NewIncomingContext(caller, metadata.Pairs(DryRunMetadataKey, "true"))
		response, err := create(dry, request)
		Expect(err).ToNot(HaveOccurred())
		Expect(response.GetClientSecret()).To(BeEmpty())
		Expect(response.GetObject().GetId()).To(BeEmpty())
		Expect(response.GetObject().GetStatus().GetClientId()).To(BeEmpty())
		var count int
		Expect(testPool.QueryRow(ctx, `select count(*) from service_accounts`).Scan(&count)).To(Succeed())
		Expect(count).To(BeZero())
	})
	DescribeTable("rejects invalid ownership and grant input before IDP work", func(change func(*publicv1.ServiceAccount)) {
		change(request.GetObject())
		_, err := create(caller, request)
		Expect(status.Code(err)).To(Or(Equal(codes.InvalidArgument), Equal(codes.PermissionDenied)))
		var count int
		Expect(testPool.QueryRow(ctx, `select count(*) from service_accounts`).Scan(&count)).To(Succeed())
		Expect(count).To(BeZero())
	}, Entry("caller ID", func(o *publicv1.ServiceAccount) { o.SetId("chosen") }),
		Entry("tenant mismatch", func(o *publicv1.ServiceAccount) { o.GetMetadata().SetTenant("foreign") }),
		Entry("project", func(o *publicv1.ServiceAccount) { o.GetMetadata().SetProject("team") }),
		Entry("unknown grant", func(o *publicv1.ServiceAccount) {
			o.SetSpec(publicv1.ServiceAccountSpec_builder{Roles: []*publicv1.RoleReference{publicv1.RoleReference_builder{Id: "unknown"}.Build()}}.Build())
		}),
		Entry("bad name", func(o *publicv1.ServiceAccount) { o.GetMetadata().SetName("Invalid_name") }))
	It("rejects a duplicate name before creating another client", func() {
		idpClient.EXPECT().CreateServiceAccountClient(gomock.Any(), gomock.Any(), testTenant).Return(clientUUID, credential, nil)
		_, err := create(caller, request)
		Expect(err).ToNot(HaveOccurred())
		response, err := create(caller, request)
		Expect(status.Code(err)).To(Equal(codes.AlreadyExists))
		Expect(response).To(BeNil())
		var count int
		Expect(testPool.QueryRow(ctx, `select count(*) from service_accounts`).Scan(&count)).To(Succeed())
		Expect(count).To(Equal(1))
	})
	It("allows only one concurrent create for a tenant and name", func() {
		idpClient.EXPECT().CreateServiceAccountClient(gomock.Any(), gomock.Any(), testTenant).Return(clientUUID, credential, nil).Times(1)
		start := make(chan struct{})
		results := make(chan codes.Code, 2)
		var workers sync.WaitGroup
		for range 2 {
			workers.Go(func() {
				defer GinkgoRecover()
				<-start
				_, err := create(caller, proto.Clone(request).(*publicv1.ServiceAccountsCreateRequest))
				results <- status.Code(err)
			})
		}
		close(start)
		workers.Wait()
		Expect([]codes.Code{<-results, <-results}).To(ConsistOf(codes.OK, codes.AlreadyExists))
	})
	It("compensates a client if persistence fails after successful setup", func() {
		_, err := testPool.Exec(ctx, `create function reject_service_account_status() returns trigger language plpgsql as $$
		begin raise exception 'test status failure'; end $$;
		create trigger reject_service_account_status before update on service_accounts
		for each row execute function reject_service_account_status()`)
		Expect(err).ToNot(HaveOccurred())
		gomock.InOrder(
			idpClient.EXPECT().CreateServiceAccountClient(gomock.Any(), gomock.Any(), testTenant).Return(clientUUID, credential, nil),
			idpClient.EXPECT().DisableServiceAccountClient(gomock.Any(), clientUUID).Return(nil),
			idpClient.EXPECT().DeleteServiceAccountClient(gomock.Any(), clientUUID).Return(nil),
		)
		response, err := create(caller, request)
		Expect(status.Code(err)).To(Equal(codes.Internal))
		Expect(response).To(BeNil())
		var count int
		Expect(testPool.QueryRow(ctx, `select count(*) from service_accounts`).Scan(&count)).To(Succeed())
		Expect(count).To(BeZero())
	})
	It("returns INTERNAL without a credential when commit fails after successful setup", func() {
		_, err := testPool.Exec(ctx, `create function reject_service_account_commit() returns trigger language plpgsql as $$
		begin raise exception 'test commit failure'; end $$;
		create constraint trigger reject_service_account_commit after insert on service_accounts
		deferrable initially deferred for each row execute function reject_service_account_commit()`)
		Expect(err).ToNot(HaveOccurred())
		var buffer bytes.Buffer
		capturedLogger := slog.New(slog.NewJSONHandler(&buffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
		tenancyLogic, err := auth.NewDefaultTenancyLogic().SetLogger(capturedLogger).Build()
		Expect(err).ToNot(HaveOccurred())
		api, err := NewServiceAccountsServer().SetLogger(capturedLogger).SetAttributionLogic(attribution).
			SetTenancyLogic(tenancyLogic).SetIdpClient(idpClient).Build()
		Expect(err).ToNot(HaveOccurred())
		logs, err := logging.NewInterceptor().SetLogger(capturedLogger).SetBodies(true).Build()
		Expect(err).ToNot(HaveOccurred())
		transactions, err := database.NewTxInterceptor().SetLogger(capturedLogger).SetManager(tm).Build()
		Expect(err).ToNot(HaveOccurred())
		server := testutils.NewServer(grpc.ChainUnaryInterceptor(logs.UnaryServer, transactions.UnaryServer,
			func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				return handler(auth.ContextWithSubject(ctx, &auth.Subject{User: "admin", Tenants: collections.NewSet(testTenant)}), req)
			}))
		publicv1.RegisterServiceAccountsServer(server.Registrar(), api)
		server.Start()
		DeferCleanup(server.Stop)
		connection, err := grpc.NewClient(server.Address(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(connection.Close)
		var clientID string
		idpClient.EXPECT().CreateServiceAccountClient(gomock.Any(), gomock.Any(), testTenant).
			DoAndReturn(func(_ context.Context, id, _ string) (string, string, error) {
				clientID = id
				return clientUUID, credential, nil
			})
		response, err := publicv1.NewServiceAccountsClient(connection).Create(caller, request)
		Expect(status.Code(err)).To(Equal(codes.Internal))
		Expect(response).To(BeNil())
		Expect(buffer.String()).ToNot(ContainSubstring(credential))
		Expect(buffer.String()).To(ContainSubstring(clientID))
		Expect(buffer.String()).To(ContainSubstring("Failed to end transaction"))
		var count int
		Expect(testPool.QueryRow(ctx, `select count(*) from service_accounts`).Scan(&count)).To(Succeed())
		Expect(count).To(BeZero())
	})

	It("uses detached bounded compensation after request cancellation", func() {
		cancelled, cancel := context.WithCancel(caller)
		defer cancel()
		idpClient.EXPECT().CreateServiceAccountClient(gomock.Any(), gomock.Any(), testTenant).
			DoAndReturn(func(context.Context, string, string) (string, string, error) {
				cancel()
				return clientUUID, "", context.Canceled
			})
		gomock.InOrder(
			idpClient.EXPECT().DisableServiceAccountClient(gomock.Any(), clientUUID).DoAndReturn(func(cleanup context.Context, _ string) error {
				Expect(cleanup.Err()).ToNot(HaveOccurred())
				_, bounded := cleanup.Deadline()
				Expect(bounded).To(BeTrue())
				return nil
			}),
			idpClient.EXPECT().DeleteServiceAccountClient(gomock.Any(), clientUUID).Return(nil),
		)
		response, err := create(cancelled, request)
		Expect(err).To(HaveOccurred())
		Expect(response).To(BeNil())
		var count int
		Expect(testPool.QueryRow(ctx, `select count(*) from service_accounts`).Scan(&count)).To(Succeed())
		Expect(count).To(BeZero())
	})

	DescribeTable("rolls back setup failures and compensates only known created clients", func(partialUUID string, cleanupFails bool) {
		idpClient.EXPECT().CreateServiceAccountClient(gomock.Any(), gomock.Any(), testTenant).Return(partialUUID, "", errors.New("upstream "+credential))
		if partialUUID != "" {
			var cleanupError error
			if cleanupFails {
				cleanupError = errors.New("cleanup " + credential)
			}
			gomock.InOrder(
				idpClient.EXPECT().DisableServiceAccountClient(gomock.Any(), clientUUID).DoAndReturn(func(ctx context.Context, _ string) error {
					Expect(ctx.Err()).ToNot(HaveOccurred())
					_, bounded := ctx.Deadline()
					Expect(bounded).To(BeTrue())
					return cleanupError
				}),
				idpClient.EXPECT().DeleteServiceAccountClient(gomock.Any(), clientUUID).Return(cleanupError),
			)
		}
		response, err := create(caller, request)
		Expect(status.Code(err)).To(Equal(codes.Unavailable))
		Expect(response).To(BeNil())
		Expect(strings.Contains(err.Error(), credential)).To(BeFalse())
		var count int
		Expect(testPool.QueryRow(ctx, `select count(*) from service_accounts`).Scan(&count)).To(Succeed())
		Expect(count).To(BeZero())
	}, Entry("no created client", "", false), Entry("partial setup", clientUUID, false), Entry("failed cleanup", clientUUID, true))
})
