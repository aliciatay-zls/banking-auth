package domain

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/errs"
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

func (c CustomClaims) IsRoleAdmin() bool {
	if c.Role == "admin" { //public claims "customer_id", "role", etc
		return true
	}
	return false
}

func (c CustomClaims) IsForbidden(route string) (bool, *errs.AppError) {
	if c.Role != "user" {
		return true, errs.NewAuthenticationError("Unknown role")
	}

	if route == "GetAllCustomers" || route == "NewAccount" {
		logger.Error("User trying to access admin-only routes")
		return true, errs.NewAuthenticationError("Access denied")
	}
	return false, nil
}

func (c CustomClaims) HasMismatch(route string, custId string, acctId string) (bool, *errs.AppError) {
	if route == "GetCustomer" {
		actualCustId := c.CustomerId
		if custId != actualCustId {
			logger.Error("User trying to access another customer's details")
			return true, errs.NewAuthenticationError("Access denied")
		}
	} else if route == "NewTransaction" {
		actualAcctId := strings.Split(c.AllAccountIds, ",")
		for _, aId := range actualAcctId {
			if acctId == aId {
				return false, nil
			}
		}
		logger.Error("User trying to make transaction for another customer's account")
		return true, errs.NewAuthenticationError("Access denied")
	}
	return false, nil
}
