package main

import (
	"context"
	"os"

	producer "github.com/asecurityteam/component-producer"
	v1 "github.com/asecurityteam/nexpose-vuln-hydrator/pkg/handlers/v1"
	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/hydrator"
	"github.com/asecurityteam/serverfull"
	"github.com/asecurityteam/settings"
)

type config struct {
	Producer   *producer.Config
	Hydrator   *hydrator.HydratorConfig
	LambdaMode bool `description:"Use the Lambda SDK to start the system."`
}

func (*config) Name() string {
	return "nexposevulnhydrator"
}

type component struct {
	Producer *producer.Component
	Hydrator *hydrator.HydratorComponent
}

func newComponent() *component {
	return &component{
		Producer: producer.NewComponent(),
		Hydrator: hydrator.NewHydratorComponent(),
	}
}

func (c *component) Settings() *config {
	return &config{
		Producer: c.Producer.Settings(),
		Hydrator: c.Hydrator.Settings(),
	}
}

func main() {
	ctx := context.Background()
	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	runner := new(func(context.Context, settings.Source) error)
	cmp := newComponent()
	err = settings.NewComponent(ctx, source, cmp, runner)
	if err != nil {
		panic(err.Error())
	}
	if err := (*runner)(ctx, source); err != nil {
		panic(err.Error())
	}
}

func (c *component) New(ctx context.Context, conf *config) (func(context.Context, settings.Source) error, error) {
	assetHydrator, err := c.Hydrator.New(ctx, conf.Hydrator)
	if err != nil {
		return nil, err
	}
	p, err := c.Producer.New(ctx, conf.Producer)
	if err != nil {
		return nil, err
	}

	hydrationHandler := &v1.HydrationHandler{
		Hydrator: assetHydrator,
		Producer: p,
	}
	handlers := map[string]serverfull.Function{
		"hydrate": serverfull.NewFunction(hydrationHandler.Handle),
	}

	fetcher := &serverfull.StaticFetcher{Functions: handlers}
	if conf.LambdaMode {
		return func(ctx context.Context, source settings.Source) error {
			return serverfull.StartLambda(ctx, source, fetcher, "attribute")
		}, nil
	}
	return func(ctx context.Context, source settings.Source) error {
		return serverfull.StartHTTP(ctx, source, fetcher)
	}, nil
}
