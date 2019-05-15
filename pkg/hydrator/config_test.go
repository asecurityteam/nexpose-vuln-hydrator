package hydrator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestName(t *testing.T) {
	nexposeClientConfig := NexposeConfig{}
	assert.Equal(t, "Nexpose", nexposeClientConfig.Name())
}

func TestComponentDefaultConfig(t *testing.T) {
	component := &NexposeConfigComponent{}
	config := component.Settings()
	assert.Empty(t, config.Host)
	assert.Empty(t, config.Username)
	assert.Empty(t, config.Password)
	assert.Equal(t, config.PageSize, 100)
}

func TestNexposeClientConfigWithValues(t *testing.T) {
	nexposeClientComponent := NexposeConfigComponent{}
	config := &NexposeConfig{
		Host:     "http://localhost",
		Username: "myusername",
		Password: "mypassword",
		PageSize: 5,
	}
	nexposeClient, err := nexposeClientComponent.New(context.Background(), config)

	assert.Equal(t, "http://localhost", nexposeClient.Host.String())
	assert.Equal(t, "myusername", nexposeClient.Username)
	assert.Equal(t, "mypassword", nexposeClient.Password)
	assert.Equal(t, 5, nexposeClient.PageSize)
	assert.Nil(t, err)
}

func TestNexposeClientConfigWithInvalidHost(t *testing.T) {
	nexposeClientComponent := NexposeConfigComponent{}
	config := &NexposeConfig{Host: "~!@#$%^&*()_+:?><!@#$%^&*())_:"}
	_, err := nexposeClientComponent.New(context.Background(), config)

	assert.Error(t, err)
}
