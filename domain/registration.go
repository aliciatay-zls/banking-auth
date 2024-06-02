package domain

import (
	"database/sql"
	"github.com/aliciatay-zls/banking-auth/dto"
	"github.com/aliciatay-zls/banking-lib/errs"
	"github.com/aliciatay-zls/banking-lib/formValidator"
	"github.com/aliciatay-zls/banking-lib/logger"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"time"
)

const FormatDateTime = "2006-01-02 15:04:05" //time.DateTime
const ResendEmailAllowedAttempts = 11        //additional 1 attempt since during registration an email is already sent
const ResendEmailAllowedInterval = time.Minute
const RetrySendEmailAttempts = 3
const RetrySendEmailInterval = time.Second * 5

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

		DateRegistered: time.Now().UTC().Format(FormatDateTime),
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
		logger.Error("Cannot resend email due to error while parsing time last emailed: " + err.Error())
		return errs.NewUnexpectedError("Unexpected server-side error")
	}
	if time.Now().UTC().Sub(lastEmailed) <= ResendEmailAllowedInterval { //no need lastEmailed.UTC(): alr stored in UTC
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
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(OneTimeTokenDuration)),
		},
		Email:          r.Email,
		DateRegistered: r.DateRegistered,
	}
}
