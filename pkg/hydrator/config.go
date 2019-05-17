package hydrator

import (
	"context"
	"net/url"
)

// NexposeConfig holds configuration to connect to Nexpose
// and make a call to the fetch assets API
type NexposeConfig struct {
	Host     string `description:"The scheme and host of a Nexpose instance."`
	Username string `description:"The username used to login to the Nexpose instance at the given host."`
	Password string `description:"The password for the corresponding username."`
	PageSize int    `description:"The number of assets that should be returned from the Nexpose API at one time."`
}

// Name is used by the settings library and will add a "NEXPOSE_"
// prefix to NexposeConfig environment variables
func (c *NexposeConfig) Name() string {
	return "Nexpose"
}

// NexposeConfigComponent satisfies the settings library Component
// API, and may be used by the settings.NewComponent function.
type NexposeConfigComponent struct{}

// Settings can be used to populate default values if there are any
func (*NexposeConfigComponent) Settings() *NexposeConfig {
	return &NexposeConfig{
		PageSize: 100,
	}
}

// New constructs a NexposeClient from a config.
func (*NexposeConfigComponent) New(_ context.Context, c *NexposeConfig) (*NexposeClient, error) {
	host, err := url.Parse(c.Host)
	if err != nil {
		return nil, err
	}

	return &NexposeClient{
		Host:     host,
		Username: c.Username,
		Password: c.Password,
		PageSize: c.PageSize,
	}, nil
}
