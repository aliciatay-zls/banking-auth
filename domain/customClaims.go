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

// IsAccessDenied performs a series of checks on the role privileges and identity sent by the client in the request
// against those in the token claims.
func (c *CustomClaims) IsAccessDenied(route string, customerId string, accountId string) bool {
	//admin can access all routes (get role from token Body)
	if c.isRoleAdmin() {
		return false
	}

	//user can only access some routes
	if c.isForbidden(route) {
		return true
	}

	//user can only access his own routes (get customer_id from token Body)
	if c.isCustomerIdMismatch(customerId) {
		logger.Error("Customer ID does not belong to client")
		return true
	}
	if route == "NewTransaction" && c.isAccountIdMismatch(accountId) {
		logger.Error("Account ID does not belong to client")
		return true
	}

	return false
}

func (c *CustomClaims) isRoleAdmin() bool {
	if c.Role == "admin" { //public claims "customer_id", "role", etc
		return true
	}
	return false
}

func (c *CustomClaims) isForbidden(route string) bool {
	if c.Role != "user" {
		logger.Error("Unknown role")
		return true
	}

	if route == "GetAllCustomers" || route == "NewAccount" {
		logger.Error("User trying to access admin-only routes")
		return true
	}
	return false
}

func (c *CustomClaims) isCustomerIdMismatch(custId string) bool {
	if custId != c.CustomerId {
		return true
	}
	return false
}

func (c *CustomClaims) isAccountIdMismatch(acctId string) bool {
	actualAcctId := strings.Split(c.AllAccountIds, ",")
	for _, aId := range actualAcctId {
		if acctId == aId {
			return false
		}
	}
	return true
}

//using pointer receivers to avoid copying values of the struct each time (many CustomClaims methods are called)
//https://go.dev/tour/methods/8
