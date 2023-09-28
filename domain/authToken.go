package domain

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
)

const SECRET = "hmacSampleSecret"

type AuthToken struct {
	accessToken *jwt.Token //use the access token to generate the refresh token
}

func GenerateAccessToken(claims CustomClaims) (string, *errs.AppError) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(SECRET))
	if err != nil {
		logger.Error("Error while signing token: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected server-side error")
	}

	return tokenString, nil
}
