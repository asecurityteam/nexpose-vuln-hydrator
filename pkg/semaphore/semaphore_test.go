package semaphore

import (
	"testing"

	"gotest.tools/assert"
)

func TestSemaphoreLockUnlock(t *testing.T) {
	s := NewSemaphore(3)
	s.Lock()
	assert.Equal(t, 1, len(s.C))
	s.Lock()
	s.Lock()
	assert.Equal(t, 3, len(s.C))
	s.Unlock()
	assert.Equal(t, 2, len(s.C))
}
