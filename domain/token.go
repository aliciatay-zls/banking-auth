package domain

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"time"
)

// Wrap token
type SessionToken struct {
	JwtToken     *jwt.Token
	CustomClaims CustomClaims
}

func GetValidToken(tokenString string) (*SessionToken, *errs.AppError) {
	if tokenString == "" {
		logger.Error("No token in url")
		return nil, errs.NewUnexpectedError("Unexpected authentication error")
	}

	claims := CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString,
		&claims,
		func(t *jwt.Token) (interface{}, error) {
			return []byte(SECRET), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}), //same as checking if Method==alg inside keyFunc?
	)
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected authentication error")
	}
	if !token.Valid {
		logger.Error("Invalid token")
		return nil, errs.NewAuthenticationError("Token is invalid")
	}

	//wrap jwt and customClaims in one object
	sessionToken := SessionToken{
		JwtToken:     token,
		CustomClaims: claims,
	}
	return &sessionToken, nil
}

func (t SessionToken) IsExpired() (bool, *errs.AppError) {
	date, err := t.CustomClaims.GetExpirationTime() //registered claims "exp", etc
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
