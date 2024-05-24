package dto

import (
	"github.com/aliciatay-zls/banking-lib/errs"
	"github.com/aliciatay-zls/banking-lib/logger"
)

type TokenStrings struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (t TokenStrings) Validate() *errs.AppError {
	if t.AccessToken == "" || t.RefreshToken == "" {
		logger.Error("Field(s) missing or empty in request body")
		return errs.NewValidationError("Field(s) missing or empty in request body: access_token, refresh_token")
	}
	return nil
}

func (t TokenStrings) ValidateRefreshToken() *errs.AppError {
	if t.RefreshToken == "" {
		logger.Error("Refresh token missing or empty in request body")
		return errs.NewValidationError("Field missing or empty in request body: refresh_token")
	}
	return nil
}
