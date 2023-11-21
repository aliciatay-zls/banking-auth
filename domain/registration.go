package domain

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"time"
)

const FormatDateTime = "2006-01-02 15:04:05"

type Registration struct { //business/domain object
	Email       string
	Id          string `db:"customer_id"`
	Name        string
	DateOfBirth string `db:"date_of_birth"` //yyyy-mm-dd
	City        string
	Zipcode     string
	Status      string

	Username string
	Password string
	Role     string

	DateRequested string `db:"requested_on"`
	DateConfirmed string `db:"confirmed_on"`
}

// NewRegistration creates a new Registration object, filling all fields except Id, Status and DateConfirmed,
// each of which have default values in the db and are to be initialized at a later step through Confirm().
func NewRegistration(req dto.RegistrationRequest) Registration {
	return Registration{
		Email:       req.Email,
		Name:        req.Name,
		DateOfBirth: req.DateOfBirth,
		City:        req.City,
		Zipcode:     req.Zipcode,

		Username: req.Username,
		Password: req.Password,
		Role:     RoleUser,

		DateRequested: time.Now().Format(FormatDateTime),
	}
}

func (r Registration) ToDTO() *dto.RegistrationResponse {
	return &dto.RegistrationResponse{
		Email:         r.Email,
		DateRequested: r.DateRequested,
	}
}

func (r Registration) Confirm(id string, date string) Registration {
	r.Id = id
	r.Status = "1"
	r.DateConfirmed = date
	return r
}

func (r Registration) oneTimeTokenClaims() OneTimeTokenClaims {
	return OneTimeTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(OneTimeTokenDuration)),
		},
		Email:         r.Email,
		Name:          r.Name,
		Username:      r.Username,
		DateRequested: r.DateRequested,
	}
}

func (r Registration) GenerateOneTimeToken() (string, *errs.AppError) {
	claims := r.oneTimeTokenClaims()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(SECRET))
	if err != nil {
		logger.Error("Error while signing one time token: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected server-side error")
	}
	return ss, nil
}
