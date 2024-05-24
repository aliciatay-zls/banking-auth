package domain

import (
	"github.com/aliciatay-zls/banking-lib/errs"
	"github.com/aliciatay-zls/banking-lib/logger"
	"golang.org/x/crypto/bcrypt"
)

// HashAndSaltPassword creates a salted hash of the given password string and returns it in string form.
// bcrypt uses salt internally (see Section 5 of paper: https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf)
func HashAndSaltPassword(pw string) (string, *errs.AppError) {
	hashedPw, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("Failed to hash and salt password")
		return "", errs.NewUnexpectedError("Unexpected server-side error")
	}

	return string(hashedPw), nil
}

func IsHashGivenPassword(hashedPw string, pw string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPw), []byte(pw)); err != nil {
		return false
	}
	return true
}
