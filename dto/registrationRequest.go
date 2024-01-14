package dto

import (
	"fmt"
	"github.com/udemy-go-1/banking-auth/formValidator"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
)

type RegistrationRequest struct {
	FirstName   string `json:"first_name" validate:"required,max=50,ascii,excludesall=0123456789"`
	LastName    string `json:"last_name" validate:"required,max=50,ascii,excludesall=0123456789"`
	CountryCode string `json:"country" validate:"required,max=100,iso3166_1_alpha2"`
	Zipcode     string `json:"zipcode" validate:"required,max=10,postcode_iso3166_alpha2_field=CountryCode"`
	DateOfBirth string `json:"date_of_birth" validate:"required,datetime=2006-01-02"`
	Email       string `json:"email" validate:"required,max=100,ascii,email"`

	Username string `json:"username" validate:"un"`
	Password string `json:"password" validate:"required,min=12,max=64,ascii"`
}

func (r RegistrationRequest) Validate() *errs.AppError {
	errMsg := map[string]string{
		"FirstName":   "Please check that the First and Last Names are correct.",
		"LastName":    "Please check that the First and Last Names are correct.",
		"CountryCode": "Please check that the Country selected is correct.",
		"Zipcode":     "Please check that the Postal/Zip Code entered is correct.",
		"DateOfBirth": "Please check that the Date of Birth entered is correct.",
		"Email":       "Please check that the Email entered is correct.",
		"Username":    "Please check that the Username meets the requirements.",
		"Password":    "Please check that the Password meets the requirements.",
	}

	if errsArr := formValidator.Struct(r); errsArr != nil {
		logger.Error(fmt.Sprintf("Registration request is invalid (%s) (%s)",
			errsArr[0].Error(), errsArr[0].ActualTag()))
		return errs.NewValidationError(errMsg[errsArr[0].Field()])
	}

	return nil
}
