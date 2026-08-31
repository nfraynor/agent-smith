package docker

import (
	"fmt"
	"strings"

	"github.com/moby/moby/client"
)

// SDKClient owns an official Docker SDK client and can be passed directly to New.
type SDKClient struct{ *client.Client }

// NewSDKClient connects to the configured Docker endpoint. An empty socket uses
// Docker's standard environment/default endpoint resolution.
func NewSDKClient(socket string) (*SDKClient, error) {
	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	if strings.TrimSpace(socket) != "" {
		opts = append(opts, client.WithHost(socket))
	}
	c, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("create docker client: %w", err)
	}
	return &SDKClient{Client: c}, nil
}
