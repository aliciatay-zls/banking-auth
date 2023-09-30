package dto

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"time"
)

type RefreshRequestDTO struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Validate checks that a request to get a new access token is valid by ensuring that the given access token is
// valid (signed by this app) and has already expired.
func (r RefreshRequestDTO) Validate() *errs.AppError {
	var validatedAccessToken *jwt.Token
	var appErr *errs.AppError
	var isAccessTokenExpired bool
	if validatedAccessToken, appErr = domain.GetValidAccessTokenFrom(r.AccessToken, true); appErr != nil {
		return appErr
	}

	isAccessTokenExpired, appErr = isExpired(validatedAccessToken)
	if appErr != nil {
		return appErr
	}
	if !isAccessTokenExpired {
		logger.Error("Access token not expired yet")
		return errs.NewAuthenticationError("Cannot generate new access token until current one expires")
	}

	return nil
}

func isExpired(token *jwt.Token) (bool, *errs.AppError) {
	date, err := token.Claims.GetExpirationTime() //registered claims "exp", etc
	if err != nil {
		logger.Error("Error while checking token's expiry time: " + err.Error())
		return false, errs.NewUnexpectedError(err.Error())
	}
	if !date.Time.After(time.Now()) { //token expiry date is before or at current time = expired
		return true, nil
	}
	return false, nil
}
