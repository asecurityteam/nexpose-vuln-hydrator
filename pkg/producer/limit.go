package producer

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
)

// SizeLimitProducer limits the size of events that can be passed
// to an underlying producer.
type SizeLimitProducer struct {
	SizeLimit int
	Wrapped   domain.Producer
}

// Produce checks the size of an event, and returns an error if it exceeds the configured limit.
// Otherwise, it passes the event through to the wrapped producer.
func (p *SizeLimitProducer) Produce(ctx context.Context, event interface{}) (interface{}, error) {
	b, e := json.Marshal(event)
	if e != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %s", e)
	}
	if len(b) > p.SizeLimit {
		return nil, ErrSizeLimitExceeded{
			Size:  len(b),
			Limit: p.SizeLimit,
		}
	}
	return p.Wrapped.Produce(ctx, event)
}
