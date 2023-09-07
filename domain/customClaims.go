package domain

import (
	"github.com/golang-jwt/jwt/v5"
)

type CustomClaims struct {
	jwt.RegisteredClaims
	Username      string `json:"username"`
	Role          string `json:"role"`
	CustomerId    string `json:"customer_id"`
	AllAccountIds string `json:"account_numbers"`
}
