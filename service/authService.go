package service

import (
	"errors"
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
	Refresh(string, string) (*dto.RefreshResponseDTO, *errs.AppError)
}

type DefaultAuthService struct { //business/domain object
	repo            domain.UserRepository  //business/domain object depends on repo (repo is a field)
	rolePermissions domain.RolePermissions //additionally depends on another business/domain object (is a field)
}

func NewDefaultAuthService(repo domain.UserRepository, rp domain.RolePermissions) DefaultAuthService {
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
	t, appErr := getValidAccessTokenFrom(requestDTO.TokenString, false)
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

// getValidAccessTokenFrom validates the token string's signature and claims such as expiry date, converting the token
// string into a JWT and storing the claims into it. An expired access token is considered valid (allowExpired is
// true) during the process of refreshing it, and invalid otherwise.
func getValidAccessTokenFrom(tokenString string, allowExpired bool) (*jwt.Token, *errs.AppError) {
	token, err := jwt.ParseWithClaims(tokenString,
		&domain.AccessTokenClaims{},
		func(t *jwt.Token) (interface{}, error) {
			return []byte(domain.SECRET), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)

	if !token.Valid {
		if errors.Is(err, jwt.ErrTokenExpired) {
			if !allowExpired {
				logger.Error("Not allowed: expired access token")
				return nil, errs.NewAuthorizationError("Access token has expired")
			}
		} else {
			if err != nil {
				logger.Error("Invalid access token: " + err.Error())
			}
			return nil, errs.NewAuthorizationError("Access token is invalid")
		}
	}
	_, ok := token.Claims.(*domain.AccessTokenClaims)
	if !ok {
		logger.Error("Error while parsing access token string with custom claims")
		return nil, errs.NewUnexpectedError("Unexpected authorization error")
	}

	return token, nil
}

// Refresh checks that the given access token is valid (signed by this app). If it has not expired, it is sent back.
// Refresh then checks that the given refresh token is valid (exists in the store). If it has expired, the access
// token is not refreshed and the client is asked to log in again to get a new refresh token. Otherwise, the given
// refresh token is used to generate a new access token.
func (s DefaultAuthService) Refresh(accessToken string, refreshToken string) (*dto.RefreshResponseDTO, *errs.AppError) {
	var validatedAccessToken *jwt.Token
	var appErr *errs.AppError
	if validatedAccessToken, appErr = getValidAccessTokenFrom(accessToken, true); appErr != nil {
		return nil, appErr
	}
	isAccessTokenExpired, appErr := isExpired(validatedAccessToken)
	if appErr != nil {
		return nil, appErr
	}
	if !isAccessTokenExpired {
		logger.Info("Sending back original access token as it has not expired yet")
		return &dto.RefreshResponseDTO{NewAccessToken: accessToken}, nil
	}

	if appErr = s.repo.FindRefreshToken(refreshToken); appErr != nil {
		return nil, appErr
	}
	var validatedRefreshToken *jwt.Token
	if validatedRefreshToken, appErr = getValidRefreshTokenFrom(refreshToken); appErr != nil {
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

func isExpired(token *jwt.Token) (bool, *errs.AppError) {
	date, err := token.Claims.GetExpirationTime() //registered claims "exp", etc
	if err != nil {
		logger.Error("Error while getting parsed token's expiry time: " + err.Error())
		return false, errs.NewUnexpectedError(err.Error())
	}
	if !date.Time.After(time.Now()) { //token expiry date is before or at current time = expired
		return true, nil
	}
	return false, nil
}

// getValidRefreshTokenFrom validates the token string's signature and claims such as expiry date, converting the token
// string into a JWT and storing the claims into it. An expired refresh token is always considered an invalid token.
func getValidRefreshTokenFrom(tokenString string) (*jwt.Token, *errs.AppError) {
	token, err := jwt.ParseWithClaims(tokenString,
		&domain.RefreshTokenClaims{},
		func(t *jwt.Token) (interface{}, error) {
			return []byte(domain.SECRET), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)

	if !token.Valid {
		if errors.Is(err, jwt.ErrTokenExpired) {
			logger.Error("Expired refresh token")
			return nil, errs.NewAuthorizationError("Session has expired, please login again")
		} else {
			if err != nil {
				logger.Error("Invalid refresh token: " + err.Error())
			}
			return nil, errs.NewAuthorizationError("Refresh token is invalid")
		}
	}
	_, ok := token.Claims.(*domain.RefreshTokenClaims)
	if !ok {
		logger.Error("Error while parsing refresh token string with custom claims")
		return nil, errs.NewUnexpectedError("Unexpected authorization error")
	}

	return token, nil
}
