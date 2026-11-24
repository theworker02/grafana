package lokiconfig

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	authtypes "github.com/grafana/authlib/types"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
)

type captureTransport struct {
	got *http.Request
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.got = req
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func TestInjectUserTransport(t *testing.T) {
	send := func(t *testing.T, ctx context.Context) (*captureTransport, *http.Request, error) {
		t.Helper()
		next := &captureTransport{}
		req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
		req.SetBasicAuth("configured", "secret-fixture")
		//nolint:bodyclose // The response has no body.
		_, err := NewInjectUserTransport(next).RoundTrip(req)
		return next, req, err
	}

	t.Run("sets the stack ID as the username and keeps the password", func(t *testing.T) {
		ctx := authtypes.WithAuthInfo(context.Background(), &identity.StaticRequester{Namespace: "stacks-123"})
		next, req, err := send(t, ctx)
		require.NoError(t, err)

		user, password, ok := next.got.BasicAuth()
		require.True(t, ok)
		require.Equal(t, "123", user)
		require.Equal(t, "secret-fixture", password)

		// The caller's request is left as it was.
		user, _, _ = req.BasicAuth()
		require.Equal(t, "configured", user)
	})

	t.Run("works with an identity.Requester", func(t *testing.T) {
		ctx := identity.WithRequester(context.Background(), &identity.StaticRequester{Namespace: "stacks-7"})
		next, _, err := send(t, ctx)
		require.NoError(t, err)
		user, _, _ := next.got.BasicAuth()
		require.Equal(t, "7", user)
	})

	t.Run("fails without auth info", func(t *testing.T) {
		next, _, err := send(t, context.Background())
		require.ErrorContains(t, err, "failed to get auth info from context")
		require.Nil(t, next.got)
	})

	for _, namespace := range []string{"default", "org-2", "invalid-namespace", "*"} {
		t.Run("fails for the namespace "+namespace, func(t *testing.T) {
			ctx := authtypes.WithAuthInfo(context.Background(), &identity.StaticRequester{Namespace: namespace})
			next, _, err := send(t, ctx)
			require.Error(t, err)
			require.Nil(t, next.got)
		})
	}
}
