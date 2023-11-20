package domain

import (
	"fmt"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"net/smtp"
)

type EmailRepository interface {
	SendConfirmationEmail(string, string) *errs.AppError
}

type EmailRepositoryDb struct {
	client     *smtp.Client
	senderAddr string
	disconnect func()
}

func NewEmailRepositoryDb(mailClient *smtp.Client, disconnectCallback func()) EmailRepositoryDb {
	return EmailRepositoryDb{client: mailClient, senderAddr: "BANK@outlook.com", disconnect: disconnectCallback}
}

// SendConfirmationEmail forms the email using the recipient's email address and unique confirmation link, registers
// the sender and recipient with the SMTP server, writes the email and closes the email writer.
func (d EmailRepositoryDb) SendConfirmationEmail(rcptAddr string, link string) *errs.AppError {
	msg := []byte("To: " + rcptAddr + "\r\n" +
		"Subject: Welcome to BANK\r\n" +
		"\r\n" +
		"Please click on the link below within the next 1 hour to complete your account registration:\n" +
		link + "\n" +
		"If it cannot be clicked, try copying it to the browser directly.\r\n")

	if err := d.client.Mail(d.senderAddr); err != nil {
		logger.Fatal("Error while starting mail transaction: " + err.Error())
	}
	if err := d.client.Rcpt(rcptAddr); err != nil {
		logger.Error(fmt.Sprintf("Error sending email to %s: %s", rcptAddr, err.Error()))
		return errs.NewUnexpectedError("Unexpected error sending confirmation email")
	}

	wc, err := d.client.Data()
	if err != nil {
		logger.Error("Error getting writer: " + err.Error())
		return errs.NewUnexpectedError("Unexpected error sending confirmation email")
	}
	if _, err = wc.Write(msg); err != nil {
		logger.Error("Error writing email: " + err.Error())
		return errs.NewUnexpectedError("Unexpected error sending confirmation email")
	}
	if err = wc.Close(); err != nil {
		logger.Error("Error closing writer: " + err.Error())
		return errs.NewUnexpectedError("Unexpected error sending confirmation email")
	}

	return nil
}
