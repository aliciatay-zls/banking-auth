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

	if customerId != "" && customerId != c.CustomerId { // (*)
		logger.Error("Customer ID does not belong to client")
		return true
	}
	if accountId != "" && c.isAccountIdMismatch(accountId) {
		logger.Error("Account ID does not belong to client")
		return true
	}
	return false
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

// (*)
//By adding the first condition in this if-stmt (same for next if-stmt), makes this method route-independent.
//No need to pass in route:
//- These 2 checks will be skipped for routes that do not require customerId or accountId (mux guarantees they will
//  be present as route variables in the first place so no need to additionally check if they were given).
//- Guard clause before these 2 if-stmts ensure that admin can go to all routes on behalf of all users (skip checks).
