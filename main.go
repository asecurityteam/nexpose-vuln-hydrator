package main

import (
	"context"
	"os"

	v1 "github.com/asecurityteam/nexpose-vuln-hydrator/pkg/handlers/v1"
	"github.com/asecurityteam/serverfull"
	"github.com/asecurityteam/settings"
)

func main() {
	ctx := context.Background()
	hydrationHandler := &v1.HydrationHandler{}
	handlers := map[string]serverfull.Function{
		"hydrate": serverfull.NewFunction(hydrationHandler.Handle),
	}

	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	fetcher := &serverfull.StaticFetcher{Functions: handlers}
	if err := serverfull.Start(ctx, source, fetcher); err != nil {
		panic(err.Error())
	}
}
