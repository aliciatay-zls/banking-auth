package service

import (
	"fmt"
	"github.com/aliciatay-zls/banking-auth/domain"
	"github.com/aliciatay-zls/banking-auth/dto"
	"github.com/aliciatay-zls/banking-lib/errs"
	"net/url"
	"os"
	"time"
)

type RegistrationService interface { //service (primary port)
	Register(dto.RegistrationRequest) (*dto.RegistrationResponse, *errs.AppError)
	CheckRegistration(string) (bool, *errs.AppError)
	ResendLink(dto.ResendRequest) *errs.AppError
	FinishRegistration(string) *errs.AppError
}

type DefaultRegistrationService struct { //business/domain object
	registrationRepo domain.RegistrationRepository
	emailRepo        domain.EmailRepository
	tokenRepo        domain.TokenRepository
}

func NewRegistrationService(regRepo domain.RegistrationRepository, emailRepo domain.EmailRepository, tokenRepo domain.TokenRepository) DefaultRegistrationService {
	return DefaultRegistrationService{regRepo, emailRepo, tokenRepo}
}

// Register uses the given dto.RegistrationRequest to check whether any of the following cases are true:
//
// 1) the given email was already used to register for an app account
//
// 2) there is already a User with the given username, or
//
// 3) there is already a Customer with the given email.
//
// If so, the request is rejected. Otherwise, it is saved to the db, and a one-time use JWT is generated to form
// a confirmation link which is then emailed to the requester.
func (s DefaultRegistrationService) Register(request dto.RegistrationRequest) (*dto.RegistrationResponse, *errs.AppError) {
	if appErr := s.registrationRepo.IsEmailUsed(request.Email); appErr != nil {
		return nil, appErr
	}
	if appErr := s.registrationRepo.IsUsernameTaken(request.Username); appErr != nil {
		return nil, appErr
	}

	hashedPw, appErr := domain.HashAndSaltPassword(request.Password)
	if appErr != nil {
		return nil, appErr
	}

	registration := domain.NewRegistration(request, hashedPw)

	if err := s.registrationRepo.Save(registration); err != nil {
		return nil, err
	}

	if err := s.createAndSendLink(registration); err != nil {
		return nil, err
	}

	return registration.ToDTO(), nil
}

func buildConfirmationURL(ott string) string {
	addr := os.Getenv("FRONTEND_SERVER_ADDRESS")
	port := os.Getenv("FRONTEND_SERVER_PORT")
	u := url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s:%s", addr, port),
		Path:   "register/check",
	}

	v := url.Values{}
	v.Add("ott", ott)
	u.RawQuery = v.Encode()

	return u.String()
}

func (s DefaultRegistrationService) createAndSendLink(reg domain.Registration) *errs.AppError {
	ott, err := s.tokenRepo.BuildToken(reg.GetOneTimeTokenClaims())
	if err != nil {
		return err
	}
	link := buildConfirmationURL(ott)

	timeEmailed, err := s.emailRepo.SendConfirmationEmail(reg.Email, link)
	if err != nil {
		return err
	}

	if err = s.registrationRepo.UpdateLastEmailedInfo(reg, timeEmailed); err != nil {
		return err
	}

	return nil
}

// CheckRegistration uses the given token's claims to check that it is valid and to try retrieving an existing
// Registration. The registration status is then returned.
func (s DefaultRegistrationService) CheckRegistration(tokenString string) (bool, *errs.AppError) {
	c, err := s.tokenRepo.GetClaimsFromToken(tokenString, domain.TokenTypeOneTime)
	if err != nil {
		return false, err
	}
	claims := c.(*domain.OneTimeTokenClaims)
	if appErr := claims.CheckExpiry(); appErr != nil {
		return false, appErr
	}

	registration, err := s.registrationRepo.FindFromEmail(claims.Email)
	if err != nil {
		return false, err
	}

	return registration.IsConfirmed(), nil
}

// ResendLink retrieves the recipient's email from the token claims if needed, tries to retrieve an existing
// Registration from the email and checks if resending the confirmation link to this email is allowed before doing so.
func (s DefaultRegistrationService) ResendLink(request dto.ResendRequest) *errs.AppError {
	var email string
	if request.Type == dto.ResendRequestTypeUsingToken {
		c, err := s.tokenRepo.GetClaimsFromToken(request.TokenString, domain.TokenTypeOneTime)
		if err != nil {
			return err
		}
		claims := c.(*domain.OneTimeTokenClaims) //no need to check expiry
		email = claims.Email
	} else if request.Type == dto.ResendRequestTypeUsingEmail {
		email = request.Email
	}

	registration, err := s.registrationRepo.FindFromEmail(email)
	if err != nil {
		return err
	}

	if err = registration.CanResendEmail(); err != nil {
		return err
	}

	if err = s.createAndSendLink(*registration); err != nil {
		return err
	}

	return nil
}

// FinishRegistration uses the given token's claims to double-check that it is valid, try retrieving an existing
// Registration, initializing the new user in the db, and filling the remaining fields of the Registration which is
// then used to update the db.
func (s DefaultRegistrationService) FinishRegistration(tokenString string) *errs.AppError {
	c, err := s.tokenRepo.GetClaimsFromToken(tokenString, domain.TokenTypeOneTime)
	if err != nil {
		return err
	}
	claims := c.(*domain.OneTimeTokenClaims)
	if appErr := claims.CheckExpiry(); appErr != nil {
		return appErr
	}

	registration, err := s.registrationRepo.FindFromEmail(claims.Email)
	if err != nil {
		return err
	}

	createTime := time.Now().Format(domain.FormatDateTime)
	customerId, err := s.registrationRepo.CreateNecessaryAccounts(registration, createTime)
	if err != nil {
		return err
	}

	completedRegistration := registration.Confirm(customerId, createTime)
	if err = s.registrationRepo.Update(completedRegistration); err != nil {
		return err
	}

	return nil
}
