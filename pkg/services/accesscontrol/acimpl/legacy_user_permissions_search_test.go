package acimpl

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authz/rbac/legacypermissions"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
)

func TestPermissionSearchPreservesResultsOnBackendError(t *testing.T) {
	want := map[int64][]accesscontrol.Permission{1: {{Action: "test:read"}}}
	cause := errors.New("search failed after loading permissions")
	client := legacypermissions.NewEmbeddedClient(nil, setting.NewCfg())
	requester := &user.SignedInUser{OrgID: 1}
	got, err := SearchUsersPermissionsViaLegacyClient(t.Context(), client, requester, accesscontrol.SearchOptions{UserID: 1},
		func(context.Context, identity.Requester, accesscontrol.SearchOptions) (map[int64][]accesscontrol.Permission, error) {
			return want, cause
		})
	require.ErrorIs(t, err, cause)
	require.Equal(t, want, got)
}
