package service

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
)

type AuthService interface { //service (primary port)
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(dto.VerifyRequest) *errs.AppError
	Refresh(dto.RefreshRequest) (*dto.RefreshResponse, *errs.AppError)
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
func (s DefaultAuthService) Login(request dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) { //business/domain object implements service
	var user *domain.User
	var appErr *errs.AppError
	if user, appErr = s.repo.Authenticate(request.Username, request.Password); appErr != nil {
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

	return &dto.LoginResponse{
		Role:         user.Role,
		CustomerId:   user.CustomerId.String,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// Verify gets a valid, non-expired JWT from the token string. It then checks the client's
// role privileges to access the route and if allowed, the client's identity.
func (s DefaultAuthService) Verify(request dto.VerifyRequest) *errs.AppError { //business/domain object implements service
	t, appErr := domain.GetValidAccessTokenFrom(request.TokenString, false)
	if appErr != nil {
		return appErr
	}

	claims := t.Claims.(*domain.AccessTokenClaims)

	//admin can access all routes (get role from token claims)
	//user can only access some routes
	if !s.rolePermissions.IsAuthorizedFor(claims.Role, request.RouteName) {
		return errs.NewAuthorizationError("Trying to access unauthorized route")
	}

	//admin can access on behalf of all users
	//user can only access his own routes (get customer_id and account_id from url, actual from token claims)
	if claims.IsIdentityMismatch(request.CustomerId, request.AccountId) {
		return errs.NewAuthorizationError("Identity mismatch between token claims and request")
	}

	return nil
}

// Refresh validates the given access token and refresh token (exists in the store and not expired).
// Refresh then checks that the overall request to get a new access token is valid (claims match).
// The validated refresh token is then used to generate a new access token.
func (s DefaultAuthService) Refresh(request dto.RefreshRequest) (*dto.RefreshResponse, *errs.AppError) {
	var accessToken, refreshToken *jwt.Token
	var appErr *errs.AppError
	if accessToken, appErr = request.ValidateAccessToken(); appErr != nil {
		return nil, appErr
	}
	if appErr = s.repo.FindRefreshToken(request.RefreshToken); appErr != nil {
		return nil, appErr
	}
	if refreshToken, appErr = domain.GetValidRefreshTokenFrom(request.RefreshToken); appErr != nil {
		return nil, appErr
	}

	accessClaims := accessToken.Claims.(*domain.AccessTokenClaims)
	refreshClaims := refreshToken.Claims.(*domain.RefreshTokenClaims)
	if domain.IsTokensMismatch(accessClaims, refreshClaims) {
		return nil, errs.NewAuthenticationErrorDueToRefreshToken()
	}

	authToken := domain.NewAuthToken(refreshClaims.AsAccessTokenClaims())
	var newAccessToken string
	if newAccessToken, appErr = authToken.GenerateAccessToken(); appErr != nil {
		return nil, appErr
	}
	return &dto.RefreshResponse{NewAccessToken: newAccessToken}, nil
}
