package legacypermissions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/grafana/authlib/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/authz/legacyclient"
	"github.com/grafana/grafana/pkg/setting"
)

func TestEmbeddedSearchPreservesRequestAndResults(t *testing.T) {
	type requestKey struct{}
	ctx := context.WithValue(t.Context(), requestKey{}, "original request")
	client := NewEmbeddedClient(nil, setting.NewCfg())
	options := accesscontrol.SearchOptions{ActionPrefix: "test:", Scope: "tests:id:one", RolePrefixes: []string{"managed:"}, ActionSets: []string{"test:group"}}
	grant := accesscontrol.Permission{
		ID: 5, RoleID: 6, Action: "test:read", Scope: "tests:id:one", Kind: "tests", Attribute: "id", Identifier: "one",
		DatasourceType: "test", Created: time.Unix(1000, 0).UTC(), Updated: time.Unix(2000, 0).UTC(),
	}
	grants := make([]accesscontrol.Permission, 1001)
	for i := range grants {
		grants[i] = grant
	}
	want := map[int64][]accesscontrol.Permission{1: nil, 2: {}, 3: grants}
	ctx = WithSearchBackend(ctx, "default", func(ctx context.Context, filters accesscontrol.SearchOptions) (map[int64][]accesscontrol.Permission, error) {
		assert.Equal(t, "original request", ctx.Value(requestKey{}))
		assert.Equal(t, options, filters)
		return want, nil
	})
	got, err := client.LegacySearchUsersPermissions(ctx, LegacySearchPermissionCaller("default"), legacyclient.LegacySearchUsersPermissionsRequest{Namespace: "default", Options: options})
	require.NoError(t, err)
	require.Equal(t, want, got.Permissions)
}

func TestEmbeddedSearchErrors(t *testing.T) {
	client := NewEmbeddedClient(nil, setting.NewCfg())
	caller := LegacySearchPermissionCaller("default")
	request := legacyclient.LegacySearchUsersPermissionsRequest{Namespace: "default"}

	t.Run("requires request binding", func(t *testing.T) {
		_, err := client.LegacySearchUsersPermissions(t.Context(), caller, request)
		require.Equal(t, codes.PermissionDenied, status.Code(err))
	})
	t.Run("preserves cause and accompanying results", func(t *testing.T) {
		cause := errors.New("query failed")
		want := map[int64][]accesscontrol.Permission{1: {{Action: "test:read"}}}
		ctx := WithSearchBackend(t.Context(), "default", func(context.Context, accesscontrol.SearchOptions) (map[int64][]accesscontrol.Permission, error) {
			return want, fmt.Errorf("reading permissions: %w", cause)
		})
		got, err := client.LegacySearchUsersPermissions(ctx, caller, request)
		require.ErrorIs(t, err, cause)
		require.EqualError(t, err, "reading permissions: query failed")
		require.Equal(t, want, got.Permissions)
	})
	t.Run("preserves cancellation", func(t *testing.T) {
		ctx := WithSearchBackend(t.Context(), "default", func(context.Context, accesscontrol.SearchOptions) (map[int64][]accesscontrol.Permission, error) {
			return nil, context.Canceled
		})
		_, err := client.LegacySearchUsersPermissions(ctx, caller, request)
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestEmbeddedSearchRepanicsOnCaller(t *testing.T) {
	client := NewEmbeddedClient(nil, setting.NewCfg())
	cause := errors.New("backend panicked")
	ctx := WithSearchBackend(t.Context(), "default", func(context.Context, accesscontrol.SearchOptions) (map[int64][]accesscontrol.Permission, error) {
		panic(cause)
	})
	require.PanicsWithValue(t, cause, func() {
		_, _ = client.LegacySearchUsersPermissions(ctx, LegacySearchPermissionCaller("default"), legacyclient.LegacySearchUsersPermissionsRequest{Namespace: "default"})
	})
}

func TestEmbeddedSearchWithDoneContext(t *testing.T) {
	client := NewEmbeddedClient(nil, setting.NewCfg())
	caller := LegacySearchPermissionCaller("default")
	request := legacyclient.LegacySearchUsersPermissionsRequest{Namespace: "default"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := client.LegacySearchUsersPermissions(ctx, caller, request)
	require.ErrorIs(t, err, context.Canceled)

	ctx, cancel = context.WithDeadline(t.Context(), time.Time{})
	defer cancel()
	_, err = client.LegacySearchUsersPermissions(ctx, caller, request)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

type cancelingSearchTransport struct {
	legacyclient.LegacyUserPermissionsClient
	cancel context.CancelFunc
}

func (c cancelingSearchTransport) LegacySearchUsersPermissions(context.Context, types.AuthInfo, legacyclient.LegacySearchUsersPermissionsRequest) (legacyclient.LegacySearchUsersPermissionsResponse, error) {
	c.cancel()
	return legacyclient.LegacySearchUsersPermissionsResponse{}, io.EOF
}

func TestEmbeddedSearchHandlesEOFDuringCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client := embeddedClient{LegacyUserPermissionsClient: cancelingSearchTransport{cancel: cancel}}

	_, err := client.LegacySearchUsersPermissions(ctx, LegacySearchPermissionCaller("default"), legacyclient.LegacySearchUsersPermissionsRequest{Namespace: "default"})
	require.ErrorIs(t, err, context.Canceled)
}

func TestEmbeddedSearchWaitsForCanceledBackend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := NewEmbeddedClient(nil, setting.NewCfg())
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		cause := errors.New("backend canceled")
		ctx = WithSearchBackend(ctx, "default", func(ctx context.Context, _ accesscontrol.SearchOptions) (map[int64][]accesscontrol.Permission, error) {
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			return nil, fmt.Errorf("%w: %w", cause, ctx.Err())
		})
		result := make(chan error, 1)
		go func() {
			_, err := client.LegacySearchUsersPermissions(ctx, LegacySearchPermissionCaller("default"), legacyclient.LegacySearchUsersPermissionsRequest{Namespace: "default"})
			result <- err
		}()
		<-started
		cancel()
		<-canceled
		synctest.Wait()
		select {
		case err := <-result:
			close(release)
			t.Fatalf("client returned while the backend was still running: %v", err)
		default:
		}
		close(release)
		err := <-result
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, cause)
	})
}
