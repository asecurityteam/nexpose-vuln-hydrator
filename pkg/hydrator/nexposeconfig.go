package hydrator

import (
	"context"
	"net/http"
	"net/url"

	httpclient "github.com/asecurityteam/component-httpclient"
)

// NexposeConfig holds configuration to connect to Nexpose
// and make a call to the fetch assets API
type NexposeConfig struct {
	HTTPClient *httpclient.Config `description:"The HTTP client config from github.com/asecurityteam/component-httpclient."`
	Host       string             `description:"The scheme and host of a Nexpose instance."`
	PageSize   int                `description:"The number of assets that should be returned from the Nexpose API at one time."`
}

// Name is used by the settings library and will add a "NEXPOSE_"
// prefix to NexposeConfig environment variables
func (c *NexposeConfig) Name() string {
	return "Nexpose"
}

// NexposeComponent satisfies the settings library Component
// API, and may be used by the settings.NewComponent function.
type NexposeComponent struct {
	HTTP *httpclient.Component
}

// NewNexposeComponent generates a NexposeComponent.
func NewNexposeComponent() *NexposeComponent {
	return &NexposeComponent{
		HTTP: httpclient.NewComponent(),
	}
}

// Settings can be used to populate default values if there are any
func (c *NexposeComponent) Settings() *NexposeConfig {
	return &NexposeConfig{
		HTTPClient: c.HTTP.Settings(),
		PageSize:   100,
	}
}

// New constructs a NexposeClient from a config.
func (c *NexposeComponent) New(ctx context.Context, config *NexposeConfig) (*NexposeClient, error) {
	rt, e := c.HTTP.New(ctx, config.HTTPClient)
	if e != nil {
		return nil, e
	}
	host, err := url.Parse(config.Host)
	if err != nil {
		return nil, err
	}

	return &NexposeClient{
		HTTPClient: &http.Client{Transport: rt},
		Host:       host,
		PageSize:   config.PageSize,
	}, nil
}
