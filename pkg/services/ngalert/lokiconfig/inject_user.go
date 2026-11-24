package lokiconfig

import (
	"errors"
	"fmt"
	"net/http"

	authtypes "github.com/grafana/authlib/types"
)

// NewInjectUserTransport returns a transport that sets the basic auth username
// of each request to the stack ID of the caller's namespace, for gateways that
// tell tenants apart by it. It keeps the request's password. Requests fail when
// the context has no caller or the caller's namespace is not a stack.
func NewInjectUserTransport(next http.RoundTripper) http.RoundTripper {
	return &injectUser{next: next}
}

type injectUser struct {
	next http.RoundTripper
}

func (t *injectUser) RoundTrip(req *http.Request) (*http.Response, error) {
	info, ok := authtypes.AuthInfoFrom(req.Context())
	if !ok {
		return nil, errors.New("failed to get auth info from context")
	}

	namespace := info.GetNamespace()
	namespaceInfo, err := authtypes.ParseNamespace(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to parse namespace %q: %w", namespace, err)
	}
	if namespaceInfo.StackID <= 0 {
		return nil, fmt.Errorf("stack id required: %q", namespace)
	}

	// A transport must not modify the caller's request.
	req = req.Clone(req.Context())
	_, password, _ := req.BasicAuth()
	req.SetBasicAuth(fmt.Sprintf("%d", namespaceInfo.StackID), password)

	return t.next.RoundTrip(req)
}
