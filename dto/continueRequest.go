package dto

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-auth/domain"
	"github.com/udemy-go-1/banking-lib/errs"
)

type ContinueRequest struct {
	TokenStrings
}

func (r ContinueRequest) Validate() (*domain.AccessTokenClaims, *errs.AppError) {
	var accessToken, refreshToken *jwt.Token
	var appErr *errs.AppError

	if accessToken, appErr = domain.GetValidAccessTokenFrom(r.AccessToken, false); appErr != nil {
		return nil, appErr
	}

	if refreshToken, appErr = domain.GetValidRefreshTokenFrom(r.RefreshToken, false); appErr != nil {
		return nil, appErr
	}

	if accessClaims, refreshClaims := domain.GetMatchedClaims(accessToken, refreshToken); accessClaims == nil || refreshClaims == nil {
		return nil, errs.NewAuthenticationErrorDueToRefreshToken()
	} else {
		return accessClaims, nil
	}
}
