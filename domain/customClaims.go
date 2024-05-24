package domain

import (
	"github.com/aliciatay-zls/banking-lib/errs"
	"github.com/aliciatay-zls/banking-lib/logger"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const AccessTokenDuration = time.Hour
const RefreshTokenDuration = time.Hour * 24 * 30 //1 month
const OneTimeTokenDuration = time.Hour
const TokenTypeRefresh = "refresh token"
const TokenTypeAccess = "access token"
const TokenTypeOneTime = "OTT"

type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Username   string `json:"username"`
	Role       string `json:"role"`
	CustomerId string `json:"customer_id"`
}

type RefreshTokenClaims struct {
	jwt.RegisteredClaims
	TokenType  string `json:"token_type"`
	Username   string `json:"un"`
	Role       string `json:"role"`
	CustomerId string `json:"cid"`
}

type OneTimeTokenClaims struct {
	jwt.RegisteredClaims
	Email          string `json:"email"`
	DateRegistered string `json:"created_on"`
}

// Validate checks the access token's expiry date and whether the role corresponds with the customer ID.
// The token must be expired to be considered valid during the process of refreshing it (wantExpired is true).
// Otherwise, it should not be expired.
func (c *AccessTokenClaims) Validate(wantExpired bool) *errs.AppError {
	isExpired := !c.ExpiresAt.After(time.Now())
	if !isExpired && wantExpired {
		logger.Error("Cannot generate new access token until current one expires")
		return errs.NewAuthenticationError("access token not expired yet")
	}
	if isExpired && !wantExpired {
		logger.Error("Expired access token")
		return errs.NewAuthenticationErrorDueToExpiredAccessToken()
	}

	if !isRoleValid(c.Role, c.CustomerId) {
		return errs.NewAuthenticationErrorDueToInvalidAccessToken()
	}

	return nil
}

// Validate checks the refresh token's expiry date, token type and whether the role corresponds with the customer ID.
// The expiry of a refresh token is ignored during the process of logging out (allowExpired is true).
// Otherwise, an expired refresh token is always considered an invalid token.
func (c *RefreshTokenClaims) Validate(allowExpired bool) *errs.AppError {
	isExpired := !c.ExpiresAt.After(time.Now())
	if isExpired && !allowExpired {
		logger.Error("Expired refresh token")
		return errs.NewAuthenticationErrorDueToRefreshToken()
	}

	if c.TokenType != TokenTypeRefresh || !isRoleValid(c.Role, c.CustomerId) {
		return errs.NewAuthenticationErrorDueToRefreshToken()
	}

	return nil
}

// CheckExpiry ensures that the one-time token is not expired as that would mean it is invalid.
func (c *OneTimeTokenClaims) CheckExpiry() *errs.AppError {
	if !c.ExpiresAt.After(time.Now()) {
		logger.Error("Expired OTT")
		return errs.NewAuthenticationError("expired OTT")
	}
	return nil
}

// isRoleValid is similar to auth.go#IsRoleValid.
func isRoleValid(role string, cid string) bool {
	if role != RoleUser && role != RoleAdmin {
		logger.Error("Token claims has unknown role")
		return false
	}
	if role == RoleUser && cid == "" {
		logger.Error("Token claims has user role but no customer ID")
		return false
	}
	if role == RoleAdmin && cid != "" {
		logger.Error("Token claims has admin role but has a customer ID")
		return false
	}
	return true
}

// IsIdentityMismatch checks, for users, the identity sent by the client in the request against
// those in the token claims.
func (c *AccessTokenClaims) IsIdentityMismatch(customerId string) bool {
	if c.Role == RoleAdmin {
		return false
	}

	if c.Role == RoleUser {
		if customerId != "" && customerId != c.CustomerId { // (*)
			logger.Error("Customer ID does not belong to client")
			return true
		}
	}

	return false
}

func (c *AccessTokenClaims) AsRefreshTokenClaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(RefreshTokenDuration)),
		},
		TokenType:  TokenTypeRefresh,
		Username:   c.Username,
		Role:       c.Role,
		CustomerId: c.CustomerId, //empty string if admin
	}
}

func (c *RefreshTokenClaims) AsAccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
		},
		Username:   c.Username,
		Role:       c.Role,
		CustomerId: c.CustomerId,
	}
}

func ArePrivateClaimsSame(accessClaims *AccessTokenClaims, refreshClaims *RefreshTokenClaims) *errs.AppError {
	if accessClaims.Username != refreshClaims.Username ||
		accessClaims.Role != refreshClaims.Role ||
		accessClaims.CustomerId != refreshClaims.CustomerId {
		logger.Error("Access token claims and refresh token claims do not match")
		return errs.NewAuthenticationErrorDueToRefreshToken()
	}

	return nil
}

//using pointer receivers to avoid copying values of the struct each time (many CustomClaims methods are called)
//https://go.dev/tour/methods/8

// (*)
//By adding the first condition in this if-stmt (same for next if-stmt), makes this method route-independent.
//No need to pass in route:
//- These 2 checks will be skipped for routes that do not require customerId or accountId (mux guarantees they will
//  be present as route variables in the first place so no need to additionally check if they were given).
//- Guard clause before these 2 if-stmts ensure that admin can go to all routes on behalf of all users (skip checks).
