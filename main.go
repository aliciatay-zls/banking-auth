package main

import (
	"github.com/udemy-go-1/banking-auth/app"
	"github.com/udemy-go-1/banking-lib/logger"
)

func main() {
	logger.Info("Starting auth server...")
	app.Start()
}
