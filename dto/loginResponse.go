package dto

type LoginResponse struct {
	IsPendingConfirmation bool   `json:"is_pending"`
	Role                  string `json:"role"`
	CustomerId            string `json:"cid"`
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
}
