package domain

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
)

type AuthToken struct {
	accessToken *jwt.Token //use the access token to generate the refresh token
}

func NewAuthToken(claims AccessTokenClaims) AuthToken {
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
	accessClaims := t.accessToken.Claims.(AccessTokenClaims)
	refreshClaims := accessClaims.AsRefreshTokenClaims()

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	tokenString, err := refreshToken.SignedString([]byte(SECRET))
	if err != nil {
		logger.Error("Error while signing refresh token: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected server-side error")
	}
	return tokenString, nil
}

// GetValidAccessTokenFrom validates the token string's signature and claims such as expiry date, converting the token
// string into a JWT and storing the claims into it. An expired access token is considered valid during the process of
// refreshing it (allowExpired is true), and invalid otherwise.
func GetValidAccessTokenFrom(tokenString string, allowExpired bool) (*jwt.Token, *errs.AppError) {
	token, err := jwt.ParseWithClaims(tokenString,
		&AccessTokenClaims{},
		func(t *jwt.Token) (interface{}, error) {
			return []byte(SECRET), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)

	if err != nil || !token.Valid {
		if !errors.Is(err, jwt.ErrTokenExpired) {
			var errReason string
			if err != nil {
				errReason = err.Error()
			}
			logger.Error("Invalid access token " + errReason)
			return nil, errs.NewAuthenticationErrorDueToInvalidAccessToken()
		}

		if !allowExpired {
			logger.Error("Expired access token")
			return nil, errs.NewAuthenticationErrorDueToExpiredAccessToken()
		}
	}

	_, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		logger.Error("Error while parsing access token string with custom claims")
		return nil, errs.NewUnexpectedError("Unexpected authorization error")
	}

	return token, nil
}

// GetValidRefreshTokenFrom validates the token string's signature and claims such as expiry date, converting the token
// string into a JWT and storing the claims into it. The expiry of a refresh token is ignored during the process of
// logging out (allowExpired is true). Otherwise, an expired refresh token is always considered an invalid token.
func GetValidRefreshTokenFrom(tokenString string, allowExpired bool) (*jwt.Token, *errs.AppError) {
	token, err := jwt.ParseWithClaims(tokenString,
		&RefreshTokenClaims{},
		func(t *jwt.Token) (interface{}, error) {
			return []byte(SECRET), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)

	if err != nil || !token.Valid {
		if !errors.Is(err, jwt.ErrTokenExpired) || !allowExpired {
			var errReason string
			if err != nil {
				errReason = err.Error()
			}
			logger.Error("Invalid or expired refresh token " + errReason)
			return nil, errs.NewAuthenticationErrorDueToRefreshToken()
		}
	}

	_, ok := token.Claims.(*RefreshTokenClaims)
	if !ok {
		logger.Error("Error while parsing refresh token string with custom claims")
		return nil, errs.NewUnexpectedError("Unexpected authorization error")
	}

	return token, nil
}
