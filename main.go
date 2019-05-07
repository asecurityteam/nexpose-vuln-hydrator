package main

import (
	"context"
	"os"

	v1 "github.com/asecurityteam/nexpose-vuln-hydrator/pkg/handlers/v1"
	serverfull "github.com/asecurityteam/serverfull/pkg"
	serverfulldomain "github.com/asecurityteam/serverfull/pkg/domain"
	"github.com/asecurityteam/settings"
	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	ctx := context.Background()
	hydrationHandler := &v1.HydrationHandler{}
	handlers := map[string]serverfulldomain.Handler{
		"hydrate": lambda.NewHandler(hydrationHandler.Handle),
	}

	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	rt, err := serverfull.NewStatic(ctx, source, handlers)
	if err != nil {
		panic(err.Error())
	}
	if err := rt.Run(); err != nil {
		panic(err.Error())
	}
}
