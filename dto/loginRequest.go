package dto

import (
	"fmt"
	"github.com/udemy-go-1/banking-auth/formValidator"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
)

type LoginRequest struct {
	Username string `json:"username" validate:"un"`
	Password string `json:"password" validate:"required,min=12,max=64,ascii"`
}

func (r LoginRequest) Validate() *errs.AppError {
	if errsArr := formValidator.Struct(r); errsArr != nil {
		logger.Error(fmt.Sprintf("Login request is invalid (%s) (%s)",
			errsArr[0].Error(), errsArr[0].ActualTag()))
		return errs.NewValidationError("Incorrect username or password")
	}
	return nil
}
