package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	cmpproducer "github.com/asecurityteam/component-producer"
	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/domain"
	v1 "github.com/asecurityteam/nexpose-vuln-hydrator/pkg/handlers/v1"
	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/hydrator"
	"github.com/asecurityteam/nexpose-vuln-hydrator/pkg/producer"
	"github.com/asecurityteam/serverfull"
	"github.com/asecurityteam/settings"
)

type config struct {
	Producer          *cmpproducer.Config
	Hydrator          *hydrator.HydratorConfig
	LambdaMode        bool `description:"Use the Lambda SDK to start the system."`
	ProducerSizeLimit int  `description:"Apply a size limit (in bytes) to the events produced by this system."`
}

func (*config) Name() string {
	return "vulnhydrator"
}

type component struct {
	Producer *cmpproducer.Component
	Hydrator *hydrator.HydratorComponent
}

func newComponent() *component {
	return &component{
		Producer: cmpproducer.NewComponent(),
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

	// Print names and example values for all defined environment variables
	// when -h or -help are passed as flags.
	fs := flag.NewFlagSet("nexpose-vuln-hydrator", flag.ContinueOnError)
	fs.Usage = func() {}
	if err = fs.Parse(os.Args[1:]); err == flag.ErrHelp {
		g, _ := settings.GroupFromComponent(cmp)
		fmt.Println("Usage: ")
		fmt.Println(settings.ExampleEnvGroups([]settings.Group{g}))
		return
	}

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

	var p domain.Producer
	p, err = c.Producer.New(ctx, conf.Producer)
	if err != nil {
		return nil, err
	}

	if conf.ProducerSizeLimit > 0 {
		p = &producer.SizeLimitProducer{
			Wrapped:   p,
			SizeLimit: conf.ProducerSizeLimit,
		}
	}
	hydrationHandler := &v1.HydrationHandler{
		Hydrator: assetHydrator,
		Producer: p,
		LogFn:    domain.LoggerFromContext,
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
