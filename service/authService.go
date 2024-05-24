package service

import (
	"github.com/aliciatay-zls/banking-auth/domain"
	"github.com/aliciatay-zls/banking-auth/dto"
	"github.com/aliciatay-zls/banking-lib/errs"
)

type AuthService interface { //service (primary port)
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Logout(string) *errs.AppError
	Verify(dto.VerifyRequest) *errs.AppError
	Refresh(dto.TokenStrings) (*dto.RefreshResponse, *errs.AppError)
	CheckAlreadyLoggedIn(dto.TokenStrings) (*dto.ContinueResponse, *errs.AppError)
}

type DefaultAuthService struct { //business/domain object
	authRepo         domain.AuthRepository         //business/domain object depends on repo (repo is a field)
	registrationRepo domain.RegistrationRepository //additionally depends on another repo (is a field)
	rolePermissions  domain.RolePermissions        //additionally depends on another business/domain object (is a field)
	tokenRepo        domain.TokenRepository        //additionally depends on another repo (is a field)
}

func NewDefaultAuthService(authRepo domain.AuthRepository, regRepo domain.RegistrationRepository, rp domain.RolePermissions, tokenRepo domain.TokenRepository) DefaultAuthService {
	return DefaultAuthService{authRepo, regRepo, rp, tokenRepo}
}

// Login authenticates the client's credentials, generating and sending back a new pair of access and refresh tokens.
// If not authenticated, it checks if the client has registered before, in which case it informs the client that
// the registration is pending email confirmation.
func (s DefaultAuthService) Login(request dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) { //business/domain object implements service
	var auth *domain.Auth
	var appErr, authErr *errs.AppError

	auth, authErr = s.authRepo.Authenticate(request.Username, request.Password)
	if authErr != nil {
		registration, err := s.registrationRepo.FindFromLoginDetails(request.Username, request.Password)
		if err != nil {
			return nil, err
		}
		if registration != nil {
			ott, genErr := s.tokenRepo.BuildToken(registration.GetOneTimeTokenClaims())
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

	accessClaims := auth.AsAccessTokenClaims()
	var accessToken, refreshToken string
	if accessToken, appErr = s.tokenRepo.BuildToken(accessClaims); appErr != nil {
		return nil, appErr
	}
	refreshClaims := accessClaims.AsRefreshTokenClaims()
	if refreshToken, appErr = s.tokenRepo.BuildToken(refreshClaims); appErr != nil {
		return nil, appErr
	}

	//hash before inserting to reduce and fix length of refresh token to 64 bytes (hex) for easier storage
	if appErr = s.authRepo.SaveRefreshTokenToStore(s.tokenRepo.GetHash(refreshToken)); appErr != nil {
		return nil, appErr
	}

	homepage, appErr := auth.GetHomepage()
	if appErr != nil {
		return nil, appErr
	}

	return &dto.LoginResponse{
		IsPendingConfirmation: false,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		Homepage:              homepage,
	}, nil
}

func (s DefaultAuthService) Logout(refreshToken string) *errs.AppError {
	c, appErr := s.tokenRepo.GetClaimsFromToken(refreshToken, domain.TokenTypeRefresh)
	if appErr != nil {
		return appErr
	}
	refreshClaims := c.(*domain.RefreshTokenClaims)

	if appErr = refreshClaims.Validate(true); appErr != nil {
		return appErr
	}

	return s.authRepo.DeleteRefreshTokenFromStore(s.tokenRepo.GetHash(refreshToken))
}

// Verify uses the claims from the given token string to check that the token is valid and non-expired.
// It then checks the client's role privileges to access the route and if allowed, the client's identity.
func (s DefaultAuthService) Verify(request dto.VerifyRequest) *errs.AppError { //business/domain object implements service
	c, appErr := s.tokenRepo.GetClaimsFromToken(request.TokenString, domain.TokenTypeAccess)
	if appErr != nil {
		return appErr
	}
	accessClaims := c.(*domain.AccessTokenClaims)
	if appErr = accessClaims.Validate(false); appErr != nil {
		return appErr
	}

	//admin can access all routes (get role from token claims)
	//user can only access some routes
	if !s.rolePermissions.IsAuthorizedFor(accessClaims.Role, request.RouteName) {
		return errs.NewAuthorizationError("Trying to access unauthorized route")
	}

	//admin can access on behalf of all users
	//user can only access his own routes (get customer_id and account_id from url, actual from token claims and db)
	if accessClaims.IsIdentityMismatch(request.CustomerId) {
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

	if _, refreshClaims, appErr = s.areTokensValid(tokenStrings, true); appErr != nil {
		return nil, appErr
	}

	isLoggedInBefore, appErr := s.authRepo.FindRefreshToken(s.tokenRepo.GetHash(tokenStrings.RefreshToken))
	if appErr != nil {
		return nil, appErr
	}
	if !isLoggedInBefore {
		return nil, errs.NewAuthenticationErrorDueToRefreshToken()
	}

	newAccessToken, appErr := s.tokenRepo.BuildToken(refreshClaims.AsAccessTokenClaims())
	if appErr != nil {
		return nil, appErr
	}

	return &dto.RefreshResponse{NewAccessToken: newAccessToken}, nil
}

// CheckAlreadyLoggedIn determines if a request to continue an already logged-in session is valid (both tokens are
// valid and claims match, and the user exists).
func (s DefaultAuthService) CheckAlreadyLoggedIn(tokenStrings dto.TokenStrings) (*dto.ContinueResponse, *errs.AppError) {
	var accessClaims *domain.AccessTokenClaims
	var appErr *errs.AppError

	if accessClaims, _, appErr = s.areTokensValid(tokenStrings, false); appErr != nil {
		return nil, appErr
	}

	auth, appErr := s.authRepo.FindUser(accessClaims.Username, accessClaims.Role, accessClaims.CustomerId)
	if appErr != nil {
		return nil, appErr
	}

	isLoggedInBefore, appErr := s.authRepo.FindRefreshToken(s.tokenRepo.GetHash(tokenStrings.RefreshToken))
	if appErr != nil {
		return nil, appErr
	}
	if !isLoggedInBefore {
		return nil, errs.NewAuthenticationErrorDueToRefreshToken()
	}

	homepage, appErr := auth.GetHomepage()
	if appErr != nil {
		return nil, appErr
	}

	return &dto.ContinueResponse{Homepage: homepage}, nil
}

// areTokensValid gets the claims for each token and checks that each are valid, before checking if both tokens
// belong to the same person using their private claims. This function always considers an expired refresh token to
// be invalid.
func (s DefaultAuthService) areTokensValid(tokenStrings dto.TokenStrings, shouldAccessTokenBeExpired bool) (*domain.AccessTokenClaims, *domain.RefreshTokenClaims, *errs.AppError) {
	c, appErr := s.tokenRepo.GetClaimsFromToken(tokenStrings.AccessToken, domain.TokenTypeAccess)
	if appErr != nil {
		return nil, nil, appErr
	}
	accessClaims := c.(*domain.AccessTokenClaims) //interface {} is map[string]interface {}, not *domain.AccessTokenClaims

	if appErr = accessClaims.Validate(shouldAccessTokenBeExpired); appErr != nil {
		return nil, nil, appErr
	}

	c, appErr = s.tokenRepo.GetClaimsFromToken(tokenStrings.RefreshToken, domain.TokenTypeRefresh)
	if appErr != nil {
		return nil, nil, appErr
	}
	refreshClaims := c.(*domain.RefreshTokenClaims)

	if appErr = refreshClaims.Validate(false); appErr != nil {
		return nil, nil, appErr
	}

	if appErr = domain.ArePrivateClaimsSame(accessClaims, refreshClaims); appErr != nil {
		return nil, nil, appErr
	}

	return accessClaims, refreshClaims, nil
}
