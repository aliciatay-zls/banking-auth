package domain

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/logger"
	"time"
)

const SECRET = "hmacSampleSecret"
const AccessTokenDuration = time.Hour
const RefreshTokenDuration = time.Hour * 24 * 30 //1 month
const OneTimeTokenDuration = time.Hour
const TokenTypeRefresh = "refresh token"

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
	Email         string `json:"email"`
	Name          string `json:"full_name"`
	Username      string `json:"username"`
	DateRequested string `json:"requested_on"`
}

func (c *AccessTokenClaims) IsPrivateClaimsValid() bool {
	return isRoleValid(c.Role, c.CustomerId)
}

func (c *RefreshTokenClaims) IsPrivateClaimsValid() bool {
	return c.TokenType == TokenTypeRefresh && isRoleValid(c.Role, c.CustomerId)
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

func GetMatchedClaims(accessToken *jwt.Token, refreshToken *jwt.Token) (*AccessTokenClaims, *RefreshTokenClaims) {
	accessClaims := accessToken.Claims.(*AccessTokenClaims)
	refreshClaims := refreshToken.Claims.(*RefreshTokenClaims)

	if accessClaims.Username != refreshClaims.Username ||
		accessClaims.Role != refreshClaims.Role ||
		accessClaims.CustomerId != refreshClaims.CustomerId {
		logger.Error("Access token claims and refresh token claims do not match")
		return nil, nil
	}

	return accessClaims, refreshClaims
}

//using pointer receivers to avoid copying values of the struct each time (many CustomClaims methods are called)
//https://go.dev/tour/methods/8

// (*)
//By adding the first condition in this if-stmt (same for next if-stmt), makes this method route-independent.
//No need to pass in route:
//- These 2 checks will be skipped for routes that do not require customerId or accountId (mux guarantees they will
//  be present as route variables in the first place so no need to additionally check if they were given).
//- Guard clause before these 2 if-stmts ensure that admin can go to all routes on behalf of all users (skip checks).
