package service

import (
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
)

type LoginService interface { //service (primary port)
	Login(dto.LoginRequestDTO) (string, *errs.AppError)
}

type DefaultLoginService struct { //business/domain object
	repo domain.UserRepository //business/domain object depends on repo (repo is a field)
}

func NewDefaultLoginService(repo domain.UserRepository) DefaultLoginService {
	return DefaultLoginService{repo}
}

func (s DefaultLoginService) Login(requestDTO dto.LoginRequestDTO) (string, *errs.AppError) { //business/domain object implements service
	user, err := s.repo.Authenticate(requestDTO.Username, requestDTO.Password)
	if err != nil {
		return "", err
	}

	token, err := s.repo.GenerateToken(user)
	if err != nil {
		return "", err
	}

	return token, nil
}
