package dto

import (
	"fmt"
	"github.com/udemy-go-1/banking-auth/formValidator"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
)

const ResendRequestTypeUsingToken = "UsingToken"
const ResendRequestTypeUsingEmail = "UsingEmail"

type ResendRequest struct {
	Type        string
	TokenString string
	Email       string `json:"email" validate:"required,max=100,ascii,email"`
}

func (r ResendRequest) Validate() *errs.AppError {
	if r.Type == ResendRequestTypeUsingToken {
		if r.TokenString == "" {
			logger.Error("No token in url")
			return errs.NewValidationError(errs.MessageMissingToken)
		}
	} else if r.Type == ResendRequestTypeUsingEmail {
		if errsArr := formValidator.Struct(r); errsArr != nil {
			logger.Error(fmt.Sprintf("Resend email request is invalid (%s) (%s)",
				errsArr[0].Error(), errsArr[0].ActualTag()))
			return errs.NewValidationError("Invalid email")
		}
	} else {
		return errs.NewUnexpectedError("Unknown resend request type")
	}

	return nil
}
