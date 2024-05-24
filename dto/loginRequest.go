package dto

import (
	"fmt"
	"github.com/aliciatay-zls/banking-lib/errs"
	"github.com/aliciatay-zls/banking-lib/formValidator"
	"github.com/aliciatay-zls/banking-lib/logger"
)

type LoginRequest struct {
	Username string `json:"username" validate:"required,max=20,ascii"`
	Password string `json:"password" validate:"required,max=64,ascii"`
}

func (r LoginRequest) Validate() *errs.AppError {
	if errsArr := formValidator.Struct(r); errsArr != nil {
		logger.Error(fmt.Sprintf("Login request is invalid (%s) (%s)",
			errsArr[0].Error(), errsArr[0].ActualTag()))
		return errs.NewValidationError("Incorrect username or password")
	}
	return nil
}
