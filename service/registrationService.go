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
}

type DefaultRegistrationService struct { //business/domain object
	registrationRepo domain.RegistrationRepository
	emailRepo        domain.EmailRepository
}

func NewRegistrationService(regRepo domain.RegistrationRepository, emailRepo domain.EmailRepository) DefaultRegistrationService {
	return DefaultRegistrationService{regRepo, emailRepo}
}

func (s DefaultRegistrationService) Register(request dto.RegistrationRequest) (*dto.RegistrationResponse, *errs.AppError) {
	registration := domain.NewRegistration(request)

	ott, err := registration.GenerateOneTimeToken()
	if err != nil {
		return nil, err
	}
	link := buildConfirmationURL(ott)

	if err = s.registrationRepo.Save(registration); err != nil {
		return nil, err
	}

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
