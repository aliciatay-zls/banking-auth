package domain

import (
	"database/sql"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"time"
)

const FormatDateTime = "2006-01-02 15:04:05"

type Registration struct { //business/domain object
	Email       string
	CustomerId  sql.NullString `db:"customer_id"`
	Name        string
	DateOfBirth string `db:"date_of_birth"` //yyyy-mm-dd
	City        string
	Zipcode     string
	Status      string

	Username string
	Password string
	Role     string

	DateRequested string         `db:"requested_on"`
	DateConfirmed sql.NullString `db:"confirmed_on"`
}

// NewRegistration creates a new Registration object, filling all fields except CustomerId, Status and DateConfirmed,
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

func (r Registration) IsConfirmed() bool {
	return r.CustomerId.Valid && r.Status == "1" && r.DateConfirmed.Valid
}

func (r Registration) Confirm(id string, date string) *Registration {
	r.CustomerId = sql.NullString{String: id}
	r.Status = "1"
	r.DateConfirmed = sql.NullString{String: date}
	return &r
}

func (r Registration) GetOneTimeTokenClaims() OneTimeTokenClaims {
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
	claims := r.GetOneTimeTokenClaims()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(SECRET))
	if err != nil {
		logger.Error("Error while signing one time token: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected server-side error")
	}
	return ss, nil
}

func ValidateOneTimeToken(tokenString string) (*OneTimeTokenClaims, *errs.AppError) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&OneTimeTokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)

	if err != nil {
		logger.Error("Error while parsing one time token: " + err.Error())
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errs.NewAuthenticationError("Expired OTT")
		}
		return nil, errs.NewAuthenticationError("Invalid OTT")
	}

	claims, ok := token.Claims.(*OneTimeTokenClaims)
	if !ok {
		logger.Error("Error while type asserting one time token claims")
		return nil, errs.NewUnexpectedError("Unexpected authorization error")
	}

	return claims, nil
}
