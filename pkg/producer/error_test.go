package producer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrSizeLimitExceeded(t *testing.T) {
	e := ErrSizeLimitExceeded{}
	require.Equal(t, "payload size 0 exceeds limit 0", e.Error())
}
