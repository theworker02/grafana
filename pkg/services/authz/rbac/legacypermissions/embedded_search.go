package legacypermissions

import (
	"context"

	"github.com/fullstorydev/grpchan/inprocgrpc"
	"github.com/grafana/authlib/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authz/legacyclient"
	authzv1 "github.com/grafana/grafana/pkg/services/authz/proto/v1"
)

type searchBackendKey struct{}

type embeddedSearchCallKey struct{}

type embeddedSearchCall struct {
	embeddedTransactionCall
	permissions map[int64][]accesscontrol.Permission
	err         error
	panicValue  any
}

func (c *embeddedClient) LegacySearchUsersPermissions(ctx context.Context, caller types.AuthInfo, req legacyclient.LegacySearchUsersPermissionsRequest) (response legacyclient.LegacySearchUsersPermissionsResponse, err error) {
	if err := ctx.Err(); err != nil {
		return legacyclient.LegacySearchUsersPermissionsResponse{}, err
	}
	call := &embeddedSearchCall{embeddedTransactionCall: embeddedTransactionCall{done: make(chan struct{})}}
	ctx = context.WithValue(ctx, embeddedTransactionCallKey{}, &call.embeddedTransactionCall)
	ctx = context.WithValue(ctx, embeddedSearchCallKey{}, call)
	defer func() {
		// Also wait on transport cancellation so the handler can finish using
		// the original request context and publish its outcome before we read it.
		call.wait()
		if call.panicValue != nil {
			panic(call.panicValue)
		}
		if call.err != nil {
			response, err = legacyclient.LegacySearchUsersPermissionsResponse{Permissions: call.permissions}, call.err
			return
		}
		if ctxErr := ctx.Err(); ctxErr != nil && err != nil {
			err = ctxErr
		}
	}()
	return c.LegacyUserPermissionsClient.LegacySearchUsersPermissions(ctx, caller, req)
}

type searchBackend struct {
	namespace string
	search    func(context.Context, accesscontrol.SearchOptions) (map[int64][]accesscontrol.Permission, error)
}

// WithSearchBackend binds the existing service to the private in-process call.
// The request's authenticated identity and effective grants stay with that service.
func WithSearchBackend(ctx context.Context, namespace string, search func(context.Context, accesscontrol.SearchOptions) (map[int64][]accesscontrol.Permission, error)) context.Context {
	return context.WithValue(ctx, searchBackendKey{}, searchBackend{namespace: namespace, search: search})
}

func (s *embeddedServer) LegacySearchUsersPermissions(req *authzv1.LegacySearchUsersPermissionsRequest, stream authzv1.LegacyAuthzService_LegacySearchUsersPermissionsServer) (err error) {
	ctx := stream.Context()
	if s.guard == nil || ctx.Value(embeddedCallKey{}) != s.guard {
		return status.Error(codes.PermissionDenied, "legacy search is embedded-only")
	}
	clientCtx := inprocgrpc.ClientContext(ctx)
	if clientCtx == nil {
		return status.Error(codes.PermissionDenied, "legacy search requires an embedded caller")
	}
	call, ok := clientCtx.Value(embeddedSearchCallKey{}).(*embeddedSearchCall)
	if !ok {
		return status.Error(codes.PermissionDenied, "legacy search requires an embedded call")
	}
	backend, ok := clientCtx.Value(searchBackendKey{}).(searchBackend)
	if !ok || backend.search == nil || req == nil || req.Namespace != backend.namespace {
		return status.Error(codes.PermissionDenied, "legacy search does not match the bound request")
	}

	// Preserve the request context used by scope resolution, DB transactions,
	// and the native IAM directory. The stream and backend share cancellation.
	clientCtx, span := tracer.Start(clientCtx, "authz.legacypermissions.LegacySearchUsersPermissions")
	defer func() {
		// Re-raise backend panics on the request goroutine, where the caller
		// already recovers them. A panic must never look like a successful EOF.
		if value := recover(); value != nil {
			call.panicValue = value
			err = status.Error(codes.Internal, "embedded legacy search panicked")
		}
		endPermissionSpan(span, err)
	}()
	results, err := backend.search(clientCtx, accesscontrol.SearchOptions{
		UserID: req.UserId, Action: req.Action, ActionPrefix: req.ActionPrefix, Scope: req.Scope,
		ActionSets: req.ActionSets, RolePrefixes: req.RolePrefixes,
	})
	if err != nil {
		// The stream carries only successful results. Preserve the backend's
		// Go error and any accompanying result for the in-process caller.
		call.permissions, call.err = results, err
		return err
	}

	for id, permissions := range results {
		if len(permissions) == 0 {
			if err := stream.Send(&authzv1.LegacySearchUsersPermissionsResponse{UserId: id, NilPermissions: permissions == nil}); err != nil {
				return err
			}
			continue
		}
		const chunkSize = 1000
		for start := 0; start < len(permissions); start += chunkSize {
			end := min(start+chunkSize, len(permissions))
			values := make([]authzv1.LegacySearchPermission, end-start)
			chunk := &authzv1.LegacySearchUsersPermissionsResponse{UserId: id, Permissions: make([]*authzv1.LegacySearchPermission, end-start)}
			for i, grant := range permissions[start:end] {
				p := &values[i]
				p.Id, p.RoleId, p.Action, p.Scope = grant.ID, grant.RoleID, grant.Action, grant.Scope
				p.Kind, p.Attribute, p.Identifier = grant.Kind, grant.Attribute, grant.Identifier
				p.DatasourceType = grant.DatasourceType
				if !grant.Created.IsZero() {
					p.Created = timestamppb.New(grant.Created)
				}
				if !grant.Updated.IsZero() {
					p.Updated = timestamppb.New(grant.Updated)
				}
				chunk.Permissions[i] = p
			}
			if err := stream.Send(chunk); err != nil {
				return err
			}
		}
	}
	return nil
}
