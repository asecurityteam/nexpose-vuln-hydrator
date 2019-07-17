package hydrator

import (
	"context"
	"testing"

	httpclient "github.com/asecurityteam/component-httpclient"
	"github.com/stretchr/testify/assert"
)

func TestName(t *testing.T) {
	nexposeClientConfig := NexposeConfig{}
	assert.Equal(t, "Nexpose", nexposeClientConfig.Name())
}

func TestComponentDefaultConfig(t *testing.T) {
	component := &NexposeComponent{HTTP: httpclient.NewComponent()}
	config := component.Settings()
	assert.Empty(t, config.Host)
	assert.Empty(t, config.Username)
	assert.Empty(t, config.Password)
	assert.Equal(t, config.PageSize, 100)
}

func TestNexposeClientConfigWithValues(t *testing.T) {
	component := &NexposeComponent{HTTP: httpclient.NewComponent()}
	config := &NexposeConfig{
		HTTPClient: component.HTTP.Settings(),
		Host:       "http://localhost",
		Username:   "myusername",
		Password:   "mypassword",
		PageSize:   5,
	}
	nexposeClient, err := component.New(context.Background(), config)
	assert.NotEmpty(t, nexposeClient.HTTPClient)
	assert.Equal(t, "http://localhost", nexposeClient.Host.String())
	assert.Equal(t, "myusername", nexposeClient.Username)
	assert.Equal(t, "mypassword", nexposeClient.Password)
	assert.Equal(t, 5, nexposeClient.PageSize)
	assert.Nil(t, err)
}

func TestNexposeClientConfigWithInvalidHost(t *testing.T) {
	component := &NexposeComponent{HTTP: httpclient.NewComponent()}
	config := &NexposeConfig{
		HTTPClient: component.HTTP.Settings(),
		Host:       "~!@#$%^&*()_+:?><!@#$%^&*())_:",
	}
	_, err := component.New(context.Background(), config)

	assert.Error(t, err)
}
