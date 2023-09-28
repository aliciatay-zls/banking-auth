package domain

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/logger"
	"strings"
)

type CustomClaims struct {
	jwt.RegisteredClaims
	Username      string `json:"username"`
	Role          string `json:"role"`
	CustomerId    string `json:"customer_id"`
	AllAccountIds string `json:"account_numbers"`
}

// IsIdentityMismatch checks, for users, the identity sent by the client in the request against
// those in the token claims.
func (c *CustomClaims) IsIdentityMismatch(customerId string, accountId string) bool {
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

func (c *CustomClaims) isAccountIdMismatch(acctId string) bool {
	actualAccounts := strings.Split(c.AllAccountIds, ",")
	for _, aId := range actualAccounts {
		if acctId == aId {
			return false
		}
	}
	return true
}

//using pointer receivers to avoid copying values of the struct each time (many CustomClaims methods are called)
//https://go.dev/tour/methods/8
