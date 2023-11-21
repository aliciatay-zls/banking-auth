package dto

import "github.com/udemy-go-1/banking-lib/errs"

type RegistrationRequest struct {
	Name        string `json:"name"`
	City        string `json:"city"`
	Zipcode     string `json:"zipcode"`
	DateOfBirth string `json:"date_of_birth"`
	Email       string `json:"email"`

	Username string `json:"username"`
	Password string `json:"password"`
}

func (r RegistrationRequest) Validate() *errs.AppError {
	//TODO
	return errs.NewValidationError("")
}
