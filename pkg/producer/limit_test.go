package producer

import (
	"context"
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func TestSizeLimitProducer_Produce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockProducer := NewMockProducer(ctrl)

	type testStruct struct {
		foo string
		bar int
	}

	tc := []struct {
		name          string
		event         interface{}
		size          int
		expectProduce bool
		producerErr   error
		expectedErr   bool
	}{
		{
			"success",
			testStruct{foo: "baz", bar: 1},
			100,
			true,
			nil,
			false,
		},
		{
			"exceed size limit",
			testStruct{foo: "baz", bar: 1},
			1,
			false,
			nil,
			true,
		},
		{
			"unmarshal error",
			map[string]interface{}{"foo": make(chan int)},
			100,
			false,
			nil,
			true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			sl := &SizeLimitProducer{
				Wrapped:   mockProducer,
				SizeLimit: tt.size,
			}
			if tt.expectProduce {
				mockProducer.EXPECT().Produce(gomock.Any(), gomock.Any()).Return(nil, tt.producerErr)
			}
			_, e := sl.Produce(context.Background(), tt.event)
			if tt.expectedErr {
				require.NotNil(t, e)
				return
			}
			require.Nil(t, e)
		})
	}

}
