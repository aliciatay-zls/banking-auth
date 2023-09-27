package service

import (
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
)

type AuthService interface { //service (primary port)
	Login(dto.LoginRequestDTO) (string, *errs.AppError)
	Verify(dto.VerifyRequestDTO) *errs.AppError
}

type DefaultAuthService struct { //business/domain object
	repo            domain.UserRepository  //business/domain object depends on repo (repo is a field)
	rolePermissions domain.RolePermissions //additionally depends on another business/domain object (is a field)
}

func NewDefaultAuthService(repo domain.UserRepository, rp domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, rp}
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

// Verify gets a valid, non-expired JWT from the token string. It then checks the client's
// role privileges to access the route and if allowed, the client's identity.
func (s DefaultAuthService) Verify(requestDTO dto.VerifyRequestDTO) *errs.AppError { //business/domain object implements service
	t, err := domain.GetValidToken(requestDTO.TokenString)
	if err != nil {
		return err
	}

	claims := t.JwtToken.Claims.(*domain.CustomClaims)

	//admin can access all routes (get role from token claims)
	//user can only access some routes
	if !s.rolePermissions.IsAuthorizedFor(claims.Role, requestDTO.RouteName) {
		return errs.NewAuthorizationError("Trying to access unauthorized route")
	}

	//admin can access on behalf of all users
	//user can only access his own routes (get customer_id and account_id from url, actual from token claims)
	if claims.IsIdentityMismatch(requestDTO.CustomerId, requestDTO.AccountId) {
		return errs.NewAuthorizationError("Identity mismatch between token claims and request")
	}

	return nil
}
