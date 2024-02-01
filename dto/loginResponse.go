package dto

type LoginResponse struct {
	IsPendingConfirmation bool   `json:"is_pending"`
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	Homepage              string `json:"homepage"`
}
