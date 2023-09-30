package domain

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/logger"
	"strings"
	"time"
)

const SECRET = "hmacSampleSecret"
const AccessTokenDuration = time.Hour
const RefreshTokenDuration = time.Hour * 24 * 30 //1 month

type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Username      string `json:"username"`
	Role          string `json:"role"`
	CustomerId    string `json:"customer_id"`
	AllAccountIds string `json:"account_numbers"`
}

type RefreshTokenClaims struct {
	jwt.RegisteredClaims
	TokenType     string `json:"token_type"`
	Username      string `json:"un"`
	Role          string `json:"role"`
	CustomerId    string `json:"cid"`
	AllAccountIds string `json:"account_numbers"`
}

// IsIdentityMismatch checks, for users, the identity sent by the client in the request against
// those in the token claims.
func (c *AccessTokenClaims) IsIdentityMismatch(customerId string, accountId string) bool {
	if c.Role == "admin" {
		return false
	}

	if c.Role == "user" {
		if customerId != c.CustomerId {
			logger.Error("Customer ID does not belong to client")
			return true
		}
		if c.isAccountIdMismatch(accountId) {
			logger.Error("Account ID does not belong to client")
			return true
		}
		return false
	}

	return true
}

func (c *AccessTokenClaims) isAccountIdMismatch(acctId string) bool {
	actualAccounts := strings.Split(c.AllAccountIds, ",")
	for _, aId := range actualAccounts {
		if acctId == aId {
			return false
		}
	}
	return true
}

func (c *AccessTokenClaims) AsRefreshTokenClaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(RefreshTokenDuration)),
		},
		TokenType:     "refresh token",
		Username:      c.Username,
		Role:          c.Role,
		CustomerId:    c.CustomerId,    //empty string if admin
		AllAccountIds: c.AllAccountIds, //empty string if admin
	}
}

func (c *RefreshTokenClaims) AsAccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
		},
		Username:      c.Username,
		Role:          c.Role,
		CustomerId:    c.CustomerId,
		AllAccountIds: c.AllAccountIds,
	}
}

func IsTokensMismatch(accessClaims *AccessTokenClaims, refreshClaims *RefreshTokenClaims) bool {
	if accessClaims.Username != refreshClaims.Username ||
		accessClaims.Role != refreshClaims.Role ||
		accessClaims.CustomerId != refreshClaims.CustomerId ||
		accessClaims.AllAccountIds != refreshClaims.AllAccountIds {
		logger.Error("Access token claims and refresh token claims do not match")
		return true
	}
	return false
}

//using pointer receivers to avoid copying values of the struct each time (many CustomClaims methods are called)
//https://go.dev/tour/methods/8
