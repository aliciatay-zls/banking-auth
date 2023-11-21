package dto

type RegistrationResponse struct {
	Email         string `json:"email"`
	DateRequested string `json:"requested_on"`
}
