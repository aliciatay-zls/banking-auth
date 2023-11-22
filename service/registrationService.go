package service

import (
	"fmt"
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
	"net/url"
	"os"
)

type RegistrationService interface { //service (primary port)
	Register(dto.RegistrationRequest) (*dto.RegistrationResponse, *errs.AppError)
	CheckRegistration(string) (bool, *errs.AppError)
}

type DefaultRegistrationService struct { //business/domain object
	registrationRepo domain.RegistrationRepository
	emailRepo        domain.EmailRepository
}

func NewRegistrationService(regRepo domain.RegistrationRepository, emailRepo domain.EmailRepository) DefaultRegistrationService {
	return DefaultRegistrationService{regRepo, emailRepo}
}

// Register uses the given dto.RegistrationRequest to check whether any of the following cases are true:
//
// 1) the given email was already used to register for an app account
//
// 2) there is already a User with the given username, or
//
// 3) there is already a Customer with the given email.
//
// If so, the request is rejected. Otherwise, it is saved to the db, and a one-time use JWT is generated to form
// a confirmation link which is then emailed to the requester.
func (s DefaultRegistrationService) Register(request dto.RegistrationRequest) (*dto.RegistrationResponse, *errs.AppError) {
	registration := domain.NewRegistration(request)

	if appErr := s.registrationRepo.IsEmailUsed(registration.Email); appErr != nil {
		return nil, appErr
	}
	if appErr := s.registrationRepo.IsUsernameTaken(registration.Username); appErr != nil {
		return nil, appErr
	}

	if err := s.registrationRepo.Save(registration); err != nil {
		return nil, err
	}

	ott, err := registration.GenerateOneTimeToken()
	if err != nil {
		return nil, err
	}
	link := buildConfirmationURL(ott)

	if appErr := s.emailRepo.SendConfirmationEmail(registration.Email, link); appErr != nil {
		return nil, appErr
	}

	return registration.ToDTO(), nil
}

func buildConfirmationURL(ott string) string {
	addr := os.Getenv("FRONTEND_SERVER_ADDRESS")
	port := os.Getenv("FRONTEND_SERVER_PORT")
	u := url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%s", addr, port),
		Path:   "signup/confirm",
	}

	v := url.Values{}
	v.Add("ott", ott)
	u.RawQuery = v.Encode()

	return u.String()
}

func (s DefaultRegistrationService) CheckRegistration(tokenString string) (bool, *errs.AppError) {
	claims, err := domain.ValidateOneTimeToken(tokenString)
	if err != nil {
		return false, err
	}

	registration, err := s.registrationRepo.GetRegistration(claims.Email, claims.Name, claims.Username)
	if err != nil {
		return false, err
	}

	return registration.IsConfirmed(), nil
}
