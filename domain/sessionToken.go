package domain

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"time"
)

const SECRET = "hmacSampleSecret"

// Wrap token
type SessionToken struct {
	JwtToken *jwt.Token
}

func GetValidToken(tokenString string) (*SessionToken, *errs.AppError) {
	//verify validity of the token: verify signature
	token, err := jwt.ParseWithClaims(tokenString,
		&CustomClaims{},
		func(t *jwt.Token) (interface{}, error) {
			return []byte(SECRET), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}), //same as checking if Method==alg inside keyFunc?
	)
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, errs.NewAuthenticationError("Token is invalid or expired")
	}

	//other checks
	if !token.Valid {
		logger.Error("Invalid token")
		return nil, errs.NewAuthenticationError("Token is invalid")
	}
	_, ok := token.Claims.(*CustomClaims)
	if !ok {
		logger.Error("Error while parsing token string with custom claims")
		return nil, errs.NewUnexpectedError("Unexpected authentication error")
	}

	sessionToken := SessionToken{token}

	//verify validity of the token: verify expiry
	isTokenExpired, appErr := sessionToken.IsExpired()
	if isTokenExpired || appErr != nil {
		return nil, appErr
	}

	return &sessionToken, nil
}

func (t *SessionToken) IsExpired() (bool, *errs.AppError) {
	date, err := t.JwtToken.Claims.GetExpirationTime() //registered claims "exp", etc
	if err != nil {
		logger.Error("Error while getting parsed token's expiry time: " + err.Error())
		return false, errs.NewUnexpectedError("Unexpected authentication error")
	}
	if !date.Time.After(time.Now()) { //token expiry date is before or at current time = expired
		logger.Error("Expired token")
		return true, errs.NewAuthenticationError("Token has expired")
	}
	return false, nil
}
