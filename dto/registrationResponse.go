package dto

type RegistrationResponse struct {
	Email string `json:"email"`
	Date  string `json:"created_on"`
}

//frontend: A confirmation email has been sent to {email}. Please check your inbox or junk folder.
