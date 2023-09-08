package service

import (
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
)

type AuthService interface { //service (primary port)
	Login(dto.LoginRequestDTO) (string, *errs.AppError)
	IsVerificationSuccess(dto.VerifyRequestDTO) (bool, *errs.AppError)
}

type DefaultAuthService struct { //business/domain object
	repo domain.UserRepository //business/domain object depends on repo (repo is a field)
}

func NewDefaultAuthService(repo domain.UserRepository) DefaultAuthService {
	return DefaultAuthService{repo}
}

func (s DefaultAuthService) Login(requestDTO dto.LoginRequestDTO) (string, *errs.AppError) { //business/domain object implements service
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

// IsVerificationSuccess gets a valid, non-expired JWT from the token string. It then calls a series of checks on
// whether the client has access to the route using the given token and request URL.
func (s DefaultAuthService) IsVerificationSuccess(requestDTO dto.VerifyRequestDTO) (bool, *errs.AppError) { //business/domain object implements service
	t, err := domain.GetValidToken(requestDTO.TokenString)
	if err != nil {
		return false, err
	}

	claims := t.JwtToken.Claims.(*domain.CustomClaims)
	if claims.IsAccessDenied(requestDTO.RouteName, requestDTO.CustomerId, requestDTO.AccountId) {
		return false, errs.NewAuthenticationError("Access denied")
	}

	return true, nil
}
