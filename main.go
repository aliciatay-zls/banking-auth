package main

import (
	"github.com/asaskevich/govalidator"
	"github.com/udemy-go-1/banking-auth/app"
	"github.com/udemy-go-1/banking-lib/logger"
)

func main() {
	logger.Info("Starting auth server...")
	govalidator.SetFieldsRequiredByDefault(true)
	app.Start()
}
