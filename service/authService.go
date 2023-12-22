package service

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-auth/dto"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
)

type AuthService interface { //service (primary port)
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Logout(string) *errs.AppError
	Verify(dto.VerifyRequest) *errs.AppError
	Refresh(dto.TokenStrings) (*dto.RefreshResponse, *errs.AppError)
	CheckAlreadyLoggedIn(dto.TokenStrings) (*dto.ContinueResponse, *errs.AppError)
}

type DefaultAuthService struct { //business/domain object
	authRepo        domain.AuthRepository         //business/domain object depends on repo (repo is a field)
	regRepo         domain.RegistrationRepository //additionally depends on another repo (is a field)
	rolePermissions domain.RolePermissions        //additionally depends on another business/domain object (is a field)
}

func NewDefaultAuthService(ar domain.AuthRepository, rr domain.RegistrationRepository, rp domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{ar, rr, rp}
}

// Login authenticates the client's credentials, generating and sending back a new pair of access and refresh tokens.
// If not authenticated, it checks if the client has registered before, in which case it informs the client that
// the registration is pending email confirmation.
func (s DefaultAuthService) Login(request dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) { //business/domain object implements service
	var auth *domain.Auth
	var appErr, authErr *errs.AppError

	auth, authErr = s.authRepo.Authenticate(request.Username, request.Password)
	if authErr != nil {
		registration, err := s.regRepo.FindFromLoginDetails(request.Username, request.Password)
		if err != nil {
			return nil, err
		}
		if registration != nil {
			ott, genErr := registration.GenerateOneTimeToken()
			if genErr != nil {
				return nil, err
			}
			return &dto.LoginResponse{IsPendingConfirmation: true, AccessToken: ott}, nil
		}
		return nil, authErr
	}

	if !auth.IsRoleValid() {
		return nil, errs.NewUnexpectedError("Unexpected server-side error")
	}

	authToken := domain.NewAuthToken(auth.AsAccessTokenClaims())
	var accessToken, refreshToken string
	if accessToken, appErr = authToken.GenerateAccessToken(); appErr != nil {
		return nil, appErr
	}
	if refreshToken, appErr = s.authRepo.GenerateRefreshTokenAndSaveToStore(authToken); appErr != nil {
		return nil, appErr
	}

	return &dto.LoginResponse{
		IsPendingConfirmation: false,
		Role:                  auth.Role,
		CustomerId:            auth.CustomerId.String,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
	}, nil
}

func (s DefaultAuthService) Logout(refreshToken string) *errs.AppError {
	if _, appErr := domain.GetValidRefreshTokenFrom(refreshToken, true); appErr != nil {
		return appErr
	}

	return s.authRepo.DeleteRefreshTokenFromStore(refreshToken)
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
	//user can only access his own routes (get customer_id and account_id from url, actual from token claims and db)
	if claims.IsIdentityMismatch(request.CustomerId) {
		return errs.NewAuthorizationError("Identity mismatch between token claims and request")
	}

	if request.AccountId != "" {
		if err := s.authRepo.IsAccountUnderCustomer(request.AccountId, request.CustomerId); err != nil {
			return err
		}
	}

	return nil
}

// Refresh checks if a request to get a new access token is valid (both tokens are valid, the client is logged in in
// the first place, both tokens' claims match), before using the validated refresh token to generate a new access token.
func (s DefaultAuthService) Refresh(tokenStrings dto.TokenStrings) (*dto.RefreshResponse, *errs.AppError) {
	var refreshClaims *domain.RefreshTokenClaims
	var appErr *errs.AppError
	if _, refreshClaims, appErr = areTokensValid(tokenStrings, true); appErr != nil {
		return nil, appErr
	}

	isLoggedInBefore, appErr := s.authRepo.FindRefreshToken(tokenStrings.RefreshToken)
	if appErr != nil {
		return nil, appErr
	}
	if !isLoggedInBefore {
		return nil, errs.NewAuthenticationErrorDueToRefreshToken()
	}

	authToken := domain.NewAuthToken(refreshClaims.AsAccessTokenClaims())
	var newAccessToken string
	if newAccessToken, appErr = authToken.GenerateAccessToken(); appErr != nil {
		return nil, appErr
	}

	return &dto.RefreshResponse{NewAccessToken: newAccessToken}, nil
}

// CheckAlreadyLoggedIn determines if a request to continue an already logged-in session is valid (both tokens are
// valid and claims match, and the user exists).
func (s DefaultAuthService) CheckAlreadyLoggedIn(tokenStrings dto.TokenStrings) (*dto.ContinueResponse, *errs.AppError) {
	var accessClaims *domain.AccessTokenClaims
	var appErr *errs.AppError

	if accessClaims, _, appErr = areTokensValid(tokenStrings, false); appErr != nil {
		return nil, appErr
	}

	if appErr = s.authRepo.FindUser(accessClaims.Username, accessClaims.Role, accessClaims.CustomerId); appErr != nil {
		return nil, appErr
	}

	isLoggedInBefore, appErr := s.authRepo.FindRefreshToken(tokenStrings.RefreshToken)
	if appErr != nil {
		return nil, appErr
	}
	if !isLoggedInBefore {
		return nil, errs.NewAuthenticationErrorDueToRefreshToken()
	}

	return &dto.ContinueResponse{Role: accessClaims.Role, CustomerId: accessClaims.CustomerId}, nil
}

// areTokensValid checks that both tokens are valid and have the same claims. This function always considers an
// expired refresh token to be invalid.
func areTokensValid(tokenStrings dto.TokenStrings, shouldAccessTokenBeExpired bool) (*domain.AccessTokenClaims, *domain.RefreshTokenClaims, *errs.AppError) {
	var accessToken, refreshToken *jwt.Token
	var appErr *errs.AppError

	if accessToken, appErr = domain.GetValidAccessTokenFrom(tokenStrings.AccessToken, shouldAccessTokenBeExpired); appErr != nil {
		return nil, nil, appErr
	}
	if shouldAccessTokenBeExpired {
		var isExpired bool
		isExpired, appErr = domain.IsExpired(accessToken)
		if appErr != nil {
			return nil, nil, appErr
		}
		if !isExpired {
			logger.Error("Cannot generate new access token until current one expires")
			return nil, nil, errs.NewAuthenticationError("access token not expired yet")
		}
	}

	if refreshToken, appErr = domain.GetValidRefreshTokenFrom(tokenStrings.RefreshToken, false); appErr != nil {
		return nil, nil, appErr
	}

	if accessClaims, refreshClaims := domain.GetMatchedClaims(accessToken, refreshToken); accessClaims == nil || refreshClaims == nil {
		return nil, nil, errs.NewAuthenticationErrorDueToRefreshToken()
	} else {
		return accessClaims, refreshClaims, nil
	}
}
