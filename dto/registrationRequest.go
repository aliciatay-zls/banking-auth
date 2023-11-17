package dto

type RegistrationRequest struct {
	Name        string `json:"name"`
	City        string `json:"city"`
	Zipcode     string `json:"zipcode"`
	DateOfBirth string `json:"date_of_birth"`
	Email       string `json:"email"`

	Username string `json:"username"`
	Password string `json:"password"`
}
