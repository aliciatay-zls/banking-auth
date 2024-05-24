package main

import (
	"github.com/aliciatay-zls/banking-auth/app"
	"github.com/aliciatay-zls/banking-lib/formValidator"
	"github.com/aliciatay-zls/banking-lib/logger"
)

func main() {
	logger.Info("Starting auth server...")
	formValidator.Create()
	app.Start()
}
