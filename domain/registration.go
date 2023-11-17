package domain

import (
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
	"time"
)

const FormatDateTime = "2006-01-02 15:04:05"

type Registration struct { //business/domain object
	Id          string `db:"customer_id"`
	Name        string
	DateOfBirth string `db:"date_of_birth"`
	Email       string
	City        string
	Zipcode     string
	Status      string

	Username string
	Password string
	Role     string
	Date     string `db:"created_on"`
}

func NewRegistration(req dto.RegistrationRequest) Registration {
	return Registration{
		Name:        req.Name,
		DateOfBirth: req.DateOfBirth,
		Email:       req.Email,
		City:        req.City,
		Zipcode:     req.Zipcode,
		Status:      "1",

		Username: req.Username,
		Password: req.Password,
		Role:     RoleUser,
		Date:     time.Now().Format(FormatDateTime),
	}
}

func (r Registration) ToDTO() *dto.RegistrationResponse {
	return &dto.RegistrationResponse{
		Email: r.Email,
		Date:  r.Date,
	}
}

type RegistrationRepository interface { //repo (secondary port)
	Process(Registration) (*Registration, *errs.AppError)
}
