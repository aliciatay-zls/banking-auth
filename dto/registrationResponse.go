package dto

type RegistrationResponse struct {
	Email          string `json:"email"`
	DateRegistered string `json:"created_on"`
}
