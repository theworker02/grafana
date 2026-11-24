package acimpl

import (
	"context"
	"fmt"

	"github.com/open-feature/go-sdk/openfeature"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authz/legacyclient"
	"github.com/grafana/grafana/pkg/services/authz/rbac/legacypermissions"
	"github.com/grafana/grafana/pkg/services/authz/zanzana/legacyscopes"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
)

func LegacyUserPermissionsSearchEnabled(ctx context.Context) bool {
	return openfeature.NewDefaultClient().Boolean(ctx, featuremgmt.FlagAuthzLegacyUserPermissionsSearch, false, openfeature.TransactionContext(ctx))
}

func SearchUsersPermissionsViaLegacyClient(ctx context.Context, client legacyclient.LegacyUserPermissionsClient, requester identity.Requester, options accesscontrol.SearchOptions, search func(context.Context, identity.Requester, accesscontrol.SearchOptions) (map[int64][]accesscontrol.Permission, error)) (map[int64][]accesscontrol.Permission, error) {
	if client == nil {
		return nil, fmt.Errorf("embedded legacy AuthZ search client is not configured")
	}
	namespace := legacyscopes.PermissionNamespace(ctx, requester)
	ctx = legacypermissions.WithSearchBackend(ctx, namespace, func(ctx context.Context, filters accesscontrol.SearchOptions) (map[int64][]accesscontrol.Permission, error) {
		return search(ctx, requester, filters)
	})
	response, err := client.LegacySearchUsersPermissions(ctx, legacypermissions.LegacySearchPermissionCaller(namespace), legacyclient.LegacySearchUsersPermissionsRequest{
		Namespace: namespace,
		Options:   options,
	})
	return response.Permissions, err
}
