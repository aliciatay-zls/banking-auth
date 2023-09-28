package domain

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"time"
)

const SECRET = "hmacSampleSecret"
const AccessTokenDuration = time.Hour
const RefreshTokenDuration = time.Hour * 24 * 30 //1 month

type AuthToken struct {
	accessToken *jwt.Token //use the access token to generate the refresh token
}

func NewAuthToken(claims CustomClaims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) //stores given claims into new token created
	return AuthToken{accessToken: token}
}

func (t AuthToken) GenerateAccessToken() (string, *errs.AppError) {
	tokenString, err := t.accessToken.SignedString([]byte(SECRET))
	if err != nil {
		logger.Error("Error while signing access token: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected server-side error")
	}
	return tokenString, nil
}

func (t AuthToken) GenerateRefreshToken() (string, *errs.AppError) {
	accessClaims := t.accessToken.Claims.(CustomClaims)
	refreshClaims := accessClaims.AsRefreshTokenClaims()

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	tokenString, err := refreshToken.SignedString([]byte(SECRET))
	if err != nil {
		logger.Error("Error while signing refresh token: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected server-side error")
	}
	return tokenString, nil
}
