package main

import (
	"context"
	"log"

	"github.com/DimTur/learning_platform/auth/cmd/sso"
)

func main() {
	ctx := context.Background()

	cmd := sso.NewServeCmd()
	if err := cmd.ExecuteContext(ctx); err != nil {
		log.Fatalf("smth went wrong: %s", err)
	}
}
