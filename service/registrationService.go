package service

import (
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
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
	//if err := request.Validate(); err != nil { //TODO: parse fields + sanitize
	//	return nil, err
	//}

	registration := domain.NewRegistration(request)

	//processedRegistration, err := s.registrationRepo.Process(registration) //TODO: don't insert into the 3 tables until confirmation done!
	//if err != nil {
	//	return nil, err
	//}

	if appErr := s.emailRepo.SendConfirmationEmail(registration.Email, "https://google.com"); appErr != nil { //TODO: generate link, insert into db, send in email
		return nil, appErr
	}

	return registration.ToDTO(), nil
}

//TODO: modify db tables to indicate registration is pending + store confirmation links
