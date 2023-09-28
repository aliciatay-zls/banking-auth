package service

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"time"
)

type AuthService interface { //service (primary port)
	Login(dto.LoginRequestDTO) (*dto.LoginResponseDTO, *errs.AppError)
	Verify(dto.VerifyRequestDTO) *errs.AppError
}

type DefaultAuthService struct { //business/domain object
	repo            domain.UserRepository  //business/domain object depends on repo (repo is a field)
	rolePermissions domain.RolePermissions //additionally depends on another business/domain object (is a field)
}

func NewDefaultAuthService(repo domain.UserRepository, rp domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, rp}
}

func (s DefaultAuthService) Login(requestDTO dto.LoginRequestDTO) (*dto.LoginResponseDTO, *errs.AppError) { //business/domain object implements service
	user, err := s.repo.Authenticate(requestDTO.Username, requestDTO.Password)
	if err != nil {
		return nil, err
	}

	token, err := domain.GenerateAccessToken(user.AsClaims())
	if err != nil {
		return nil, err
	}

	return &dto.LoginResponseDTO{AccessToken: token}, nil
}

// Verify gets a valid, non-expired JWT from the token string. It then checks the client's
// role privileges to access the route and if allowed, the client's identity.
func (s DefaultAuthService) Verify(requestDTO dto.VerifyRequestDTO) *errs.AppError { //business/domain object implements service
	t, err := getValidTokenFrom(requestDTO.TokenString)
	if err != nil {
		return err
	}

	claims := t.Claims.(*domain.CustomClaims)

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

func getValidTokenFrom(tokenString string) (*jwt.Token, *errs.AppError) {
	//verify validity of the token: verify signature
	token, err := jwt.ParseWithClaims(tokenString,
		&domain.CustomClaims{},
		func(t *jwt.Token) (interface{}, error) {
			return []byte(domain.SECRET), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}), //same as checking if Method==alg inside keyFunc?
	)
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, errs.NewAuthorizationError(err.Error())
	}

	//other checks
	if !token.Valid {
		logger.Error("Invalid token")
		return nil, errs.NewAuthorizationError("Token is invalid")
	}
	_, ok := token.Claims.(*domain.CustomClaims)
	if !ok {
		logger.Error("Error while parsing token string with custom claims")
		return nil, errs.NewUnexpectedError("Unexpected authorization error")
	}

	//verify validity of the token: verify expiry
	isTokenExpired, appErr := isExpired(token)
	if isTokenExpired || appErr != nil {
		return nil, appErr
	}

	return token, nil
}

func isExpired(token *jwt.Token) (bool, *errs.AppError) {
	date, err := token.Claims.GetExpirationTime() //registered claims "exp", etc
	if err != nil {
		logger.Error("Error while getting parsed token's expiry time: " + err.Error())
		return false, errs.NewUnexpectedError(err.Error())
	}
	if !date.Time.After(time.Now()) { //token expiry date is before or at current time = expired
		logger.Error("Expired token")
		return true, errs.NewAuthorizationError("Token has expired")
	}
	return false, nil
}
