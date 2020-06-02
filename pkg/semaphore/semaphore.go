package semaphore

// https://developer.atlassian.com/platform/security/guides/go/patterns/#limiting-concurrent-work
//
// Semaphore implements the sync.Locker interface
// to help with concurrency control.
//
// The buffer size of C defines the max concurrent callers
// of Lock.
type Semaphore struct {
	C chan interface{}
}

// NewSempahore constructs a lock that allows `size` concurrent holders
// of the lock.
func NewSemaphore(size int) *Semaphore {
	return &Semaphore{C: make(chan interface{}, size)}
}

// Lock attempts to acquire the semaphore. If the limit has not
// yet been reached then the call returns immediately. If the
// limit is reached then this call blocks until the number of
// concurrent lock holders crosses back under the limit.
func (c Semaphore) Lock() {
	c.C <- nil
}

// Unlock indicates that the caller no longer needs space in
// the semaphore. This must be called at the end of a critical
// section just like any other Locker implementation.
func (c Semaphore) Unlock() {
	<-c.C
}
