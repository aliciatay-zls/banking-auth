package domain

import (
	"database/sql"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-auth/formValidator"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"strings"
	"time"
)

const FormatDateTime = "2006-01-02 15:04:05"
const ResendEmailAllowedAttempts = 11 //additional 1 attempt since during registration an email is already sent
const ResendEmailAllowedInterval = time.Minute

type Registration struct { //business/domain object
	Email       string
	CustomerId  sql.NullString `db:"customer_id"`
	Name        string
	DateOfBirth string `db:"date_of_birth"` //yyyy-mm-dd
	Country     string
	Zipcode     string
	Status      string

	Username       string
	HashedPassword string `db:"password"`
	Role           string

	EmailAttempts int `db:"email_attempts"` //to reset daily using pipeline

	DateRegistered  string         `db:"created_on"`
	DateLastEmailed string         `db:"last_emailed_on"`
	DateConfirmed   sql.NullString `db:"confirmed_on"`
}

// NewRegistration creates a new Registration object, filling all fields except CustomerId, Status and DateConfirmed,
// each of which have default values in the db and are to be initialized at a later step through Confirm().
func NewRegistration(req dto.RegistrationRequest, hashedPw string) Registration {
	return Registration{
		Email:       req.Email,
		Name:        strings.Join([]string{req.FirstName, req.LastName}, " "),
		DateOfBirth: req.DateOfBirth,
		Country:     formValidator.GetCountryFrom(req.CountryCode),
		Zipcode:     req.Zipcode,

		Username:       req.Username,
		HashedPassword: hashedPw,
		Role:           RoleUser,

		DateRegistered: time.Now().Format(FormatDateTime),
	}
}

func (r Registration) ToDTO() *dto.RegistrationResponse {
	return &dto.RegistrationResponse{
		Email:          r.Email,
		DateRegistered: r.DateRegistered,
	}
}

func (r Registration) CanResendEmail() *errs.AppError {
	if r.IsConfirmed() {
		logger.Error("Cannot resend email as registration is already confirmed")
		return errs.NewValidationError("Already confirmed")
	}

	if r.EmailAttempts >= ResendEmailAllowedAttempts {
		logger.Error("Cannot resend email as maximum daily attempts reached")
		return errs.NewValidationError("Maximum daily attempts reached")
	}

	lastEmailed, err := time.Parse(FormatDateTime, r.DateLastEmailed)
	if err != nil {
		logger.Error("Cannot resend email due to error while parsing last emailed time to time object")
		return errs.NewUnexpectedError("Unexpected server-side error")
	}

	if time.Now().Sub(lastEmailed) <= ResendEmailAllowedInterval {
		logger.Error("Cannot resend email as attempts made are too frequent")
		return errs.NewValidationError("Too many attempts")
	}

	return nil
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
		Email:          r.Email,
		Name:           r.Name,
		Username:       r.Username,
		DateRegistered: r.DateRegistered,
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

func ValidateOneTimeToken(tokenString string, allowExpired bool) (*OneTimeTokenClaims, *errs.AppError) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&OneTimeTokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)

	if err != nil {
		if !errors.Is(err, jwt.ErrTokenExpired) {
			logger.Error("Error while parsing one time token: " + err.Error())
			return nil, errs.NewAuthenticationError("Invalid OTT")
		}
		if errors.Is(err, jwt.ErrTokenExpired) && !allowExpired {
			logger.Error("Expired OTT")
			return nil, errs.NewAuthenticationError("Expired OTT")
		}
	}

	claims, ok := token.Claims.(*OneTimeTokenClaims)
	if !ok {
		logger.Error("Error while type asserting one time token claims")
		return nil, errs.NewUnexpectedError("Unexpected authorization error")
	}

	return claims, nil
}
