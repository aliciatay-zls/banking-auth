package main

import (
	"banking-auth/app"
	"github.com/aliciatay-zls/banking/logger"
)

func main() {
	logger.Info("Starting auth server...")
	app.Start()
}
