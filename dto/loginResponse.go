package dto

type LoginResponse struct {
	Role         string `json:"role"`
	CustomerId   string `json:"cid"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
