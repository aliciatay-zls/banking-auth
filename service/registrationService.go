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
	repo domain.RegistrationRepository
}

func NewRegistrationService(repo domain.RegistrationRepository) DefaultRegistrationService {
	return DefaultRegistrationService{repo}
}

func (s DefaultRegistrationService) Register(request dto.RegistrationRequest) (*dto.RegistrationResponse, *errs.AppError) {
	//if err := request.Validate(); err != nil { //TODO: parse fields + sanitize
	//	return nil, err
	//}

	registration := domain.NewRegistration(request)

	completedRegistration, err := s.repo.Process(registration)
	if err != nil {
		return nil, err
	}

	return completedRegistration.ToDTO(), nil
}
