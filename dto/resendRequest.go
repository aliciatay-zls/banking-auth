package dto

const ResendRequestTypeUsingToken = "UsingToken"
const ResendRequestTypeUsingEmail = "UsingEmail"

type ResendRequest struct {
	Type        string
	TokenString string
	Email       string `json:"email"`
}
