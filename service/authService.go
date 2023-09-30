package service

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
)

type AuthService interface { //service (primary port)
	Login(dto.LoginRequestDTO) (*dto.LoginResponseDTO, *errs.AppError)
	Verify(dto.VerifyRequestDTO) *errs.AppError
	Refresh(dto.RefreshRequestDTO) (*dto.RefreshResponseDTO, *errs.AppError)
}

type DefaultAuthService struct { //business/domain object
	repo            domain.AuthRepository  //business/domain object depends on repo (repo is a field)
	rolePermissions domain.RolePermissions //additionally depends on another business/domain object (is a field)
}

func NewDefaultAuthService(repo domain.AuthRepository, rp domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, rp}
}

// Login checks the client's credentials and if authenticated, generates and sends back a new pair of access and
// refresh tokens for the client.
func (s DefaultAuthService) Login(requestDTO dto.LoginRequestDTO) (*dto.LoginResponseDTO, *errs.AppError) { //business/domain object implements service
	var user *domain.User
	var appErr *errs.AppError
	if user, appErr = s.repo.Authenticate(requestDTO.Username, requestDTO.Password); appErr != nil {
		return nil, appErr
	}

	authToken := domain.NewAuthToken(user.AsAccessTokenClaims())
	var accessToken, refreshToken string
	if accessToken, appErr = authToken.GenerateAccessToken(); appErr != nil {
		return nil, appErr
	}
	if refreshToken, appErr = s.repo.GenerateRefreshTokenAndSaveToStore(authToken); appErr != nil {
		return nil, appErr
	}
	return &dto.LoginResponseDTO{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

// Verify gets a valid, non-expired JWT from the token string. It then checks the client's
// role privileges to access the route and if allowed, the client's identity.
func (s DefaultAuthService) Verify(requestDTO dto.VerifyRequestDTO) *errs.AppError { //business/domain object implements service
	t, appErr := domain.GetValidAccessTokenFrom(requestDTO.TokenString, false)
	if appErr != nil {
		return appErr
	}

	claims := t.Claims.(*domain.AccessTokenClaims)

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

// Refresh validates the request to get a new access token. Refresh then checks that the given refresh token is valid
// (exists in the store) and not expired. The validated refresh token is then used to generate a new access token.
func (s DefaultAuthService) Refresh(requestDTO dto.RefreshRequestDTO) (*dto.RefreshResponseDTO, *errs.AppError) {
	if appErr := requestDTO.Validate(); appErr != nil {
		return nil, appErr
	}

	var validatedRefreshToken *jwt.Token
	var appErr *errs.AppError
	if appErr = s.repo.FindRefreshToken(requestDTO.RefreshToken); appErr != nil {
		return nil, appErr
	}
	if validatedRefreshToken, appErr = domain.GetValidRefreshTokenFrom(requestDTO.RefreshToken); appErr != nil {
		return nil, appErr
	}

	refreshClaims := validatedRefreshToken.Claims.(*domain.RefreshTokenClaims)
	authToken := domain.NewAuthToken(refreshClaims.AsAccessTokenClaims())
	var newAccessToken string
	if newAccessToken, appErr = authToken.GenerateAccessToken(); appErr != nil {
		return nil, appErr
	}
	return &dto.RefreshResponseDTO{NewAccessToken: newAccessToken}, nil
}
