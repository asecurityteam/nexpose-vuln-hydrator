package main

import (
	"context"
	"os"

	v1 "github.com/asecurityteam/nexpose-vuln-hydrator/pkg/handlers/v1"
	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/hydrator"
	"github.com/asecurityteam/serverfull"
	"github.com/asecurityteam/settings"
)

func main() {
	ctx := context.Background()
	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	nexposeConfigComponent := hydrator.NexposeConfigComponent{}
	nexposeClient := new(hydrator.NexposeClient)
	if err = settings.NewComponent(context.Background(), source, nexposeConfigComponent, nexposeClient); err != nil {
		panic(err.Error())
	}
	assetHydrator := hydrator.NewHydrator(nexposeClient)
	hydrationHandler := &v1.HydrationHandler{Hydrator: assetHydrator}
	handlers := map[string]serverfull.Function{
		"hydrate": serverfull.NewFunction(hydrationHandler.Handle),
	}

	fetcher := &serverfull.StaticFetcher{Functions: handlers}
	if err := serverfull.Start(ctx, source, fetcher); err != nil {
		panic(err.Error())
	}
}
