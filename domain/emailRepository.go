package domain

import (
	"crypto/tls"
	"fmt"
	"github.com/aliciatay-zls/banking-lib/errs"
	"github.com/aliciatay-zls/banking-lib/logger"
	"net/smtp"
	"os"
	"time"
)

type EmailRepository interface { //repo (secondary port)
	SendConfirmationEmail(string, string) (string, *errs.AppError)
}

type DefaultEmailRepository struct { //adapter
	serverUser     string
	serverPassword string
	senderEmail    string
}

func NewDefaultEmailRepository() DefaultEmailRepository {
	return DefaultEmailRepository{
		serverUser:     os.Getenv("MAIL_SERVER_USER"),
		serverPassword: os.Getenv("MAIL_SERVER_PASSWORD"),
		senderEmail:    os.Getenv("MAIL_SENDER"),
	}
}

// SendConfirmationEmail opens a new connection with the remote SMTP server, initiates use of TLS and authenticates
// itself to the server in production mode, registers the sender and recipient, then sends the email body.
// It returns the time the email was sent.
func (d DefaultEmailRepository) SendConfirmationEmail(rcptAddr string, link string) (string, *errs.AppError) {
	mailServerAddr := os.Getenv("MAIL_SERVER_ADDRESS")
	mailServerPort := os.Getenv("MAIL_SERVER_PORT")
	addr := fmt.Sprintf("%s:%s", mailServerAddr, mailServerPort)

	client, err := smtp.Dial(addr)
	if err != nil {
		logger.Error("Error while connecting to SMTP server: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
	}

	if os.Getenv("APP_ENV") == "production" {
		logger.Info("Initiating TLS session with remote SMTP server...")
		tlsConfig := &tls.Config{ServerName: mailServerAddr}
		if err = client.StartTLS(tlsConfig); err != nil {
			logger.Error("Error initiating TLS session: " + err.Error())
			return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
		}

		logger.Info("Authenticating with remote SMTP server...")
		auth := smtp.PlainAuth("", d.serverUser, d.serverPassword, mailServerAddr)
		if err = client.Auth(auth); err != nil {
			logger.Error("Error authenticating with mail server: " + err.Error())
			return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
		}
	}

	if err = client.Mail(d.senderEmail); err != nil {
		logger.Error("Error while setting the sender: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
	}
	if err = client.Rcpt(rcptAddr); err != nil {
		logger.Error(fmt.Sprintf("Error setting the recipient %s: %s", rcptAddr, err.Error()))
		return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
	}

	wc, err := client.Data()
	if err != nil {
		logger.Error("Error getting writer: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
	}
	if _, err = wc.Write([]byte(d.buildEmail(rcptAddr, link))); err != nil {
		logger.Error("Error sending email body: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
	}
	if err = wc.Close(); err != nil {
		logger.Error("Error closing writer: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
	}

	if err = client.Quit(); err != nil {
		logger.Error("Error while closing connection to SMTP server: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
	}

	return time.Now().Format(FormatDateTime), nil
}

// buildEmail forms the email using the recipient's email address and unique confirmation link.
func (d DefaultEmailRepository) buildEmail(rcptAddr string, link string) string {
	return "From: " + d.senderEmail + "\r\n" +
		"To: " + rcptAddr + "\r\n" +
		"Subject: Email Confirmation [action required]\r\n" +
		"\r\n" +
		"Please click on the link below within the next 1 hour to complete your account registration:\n" +
		link + "\n" +
		"If it cannot be clicked, copy and paste it into the address bar of your web browser.\r\n"
}
