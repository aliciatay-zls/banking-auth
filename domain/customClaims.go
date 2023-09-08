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
	//admin can access all routes (get role from token claims)
	if c.isRoleAdmin() {
		return false
	}

	//user can only access some routes
	if c.isForbidden(route) {
		return true
	}

	//user can only access his own routes (get customer_id from url, actual from token claims)
	if c.isCustomerIdMismatch(customerId) {
		logger.Error("Customer ID does not belong to client")
		return true
	}
	//and his own account (get account_id from url, actual account_numbers from token claims)
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
