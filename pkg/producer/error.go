package producer

import "fmt"

// ErrSizeLimitExceeded is returned when an event exceeds the defined
// size limit.
type ErrSizeLimitExceeded struct {
	Size  int
	Limit int
}

func (e ErrSizeLimitExceeded) Error() string {
	return fmt.Sprintf("payload size %d exceeds limit %d", e.Size, e.Limit)
}
