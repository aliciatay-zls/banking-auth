package domain

import (
	"crypto/tls"
	"fmt"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"net/smtp"
	"os"
	"time"
)

type EmailRepository interface { //repo (secondary port)
	SendConfirmationEmail(string, string) (string, *errs.AppError)
}

type DefaultEmailRepository struct { //adapter
	client         *smtp.Client
	serverUser     string
	serverPassword string
	senderEmail    string
	disconnect     func()
}

func NewDefaultEmailRepository(mailClient *smtp.Client, disconnectCallback func()) DefaultEmailRepository {
	return DefaultEmailRepository{
		client:         mailClient,
		serverUser:     os.Getenv("MAIL_SERVER_USER"),
		serverPassword: os.Getenv("MAIL_SERVER_PASSWORD"),
		senderEmail:    os.Getenv("MAIL_SENDER"),
		disconnect:     disconnectCallback,
	}
}

// SendConfirmationEmail registers the sender and recipient with the SMTP server before writing the email and
// closing the email writer. It returns the time the email was sent.
func (d DefaultEmailRepository) SendConfirmationEmail(rcptAddr string, link string) (string, *errs.AppError) {
	if os.Getenv("APP_ENV") == "production" {
		mailServerAddr := os.Getenv("MAIL_SERVER_ADDRESS")
		mailServerPort := os.Getenv("MAIL_SERVER_PORT")
		addr := fmt.Sprintf("%s:%s", mailServerAddr, mailServerPort)

		//inform server to use TLS connection from here on
		tlsConfig := &tls.Config{ServerName: mailServerAddr}
		if err := d.client.StartTLS(tlsConfig); err != nil {
			logger.Error("Error initiating TLS session: " + err.Error())
			return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
		}

		//build email to be sent
		msg := []byte(d.buildEmail(rcptAddr, link))

		//login to remote mail server
		auth := smtp.PlainAuth("", d.serverUser, d.serverPassword, mailServerAddr)

		//send email to 1 recipient
		if err := smtp.SendMail(addr, auth, d.senderEmail, []string{rcptAddr}, msg); err != nil {
			logger.Error(fmt.Sprintf("Error sending email to %s: %s", rcptAddr, err.Error()))
			return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
		}
	} else {
		if err := d.client.Mail(d.senderEmail); err != nil {
			logger.Fatal("Error while starting mail transaction: " + err.Error())
		}
		if err := d.client.Rcpt(rcptAddr); err != nil {
			logger.Error(fmt.Sprintf("Error sending email to %s: %s", rcptAddr, err.Error()))
			return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
		}

		wc, err := d.client.Data()
		if err != nil {
			logger.Error("Error getting writer: " + err.Error())
			return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
		}
		if _, err = wc.Write([]byte(d.buildEmail(rcptAddr, link))); err != nil {
			logger.Error("Error writing email: " + err.Error())
			return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
		}
		if err = wc.Close(); err != nil {
			logger.Error("Error closing writer: " + err.Error())
			return "", errs.NewUnexpectedError("Unexpected error sending confirmation email")
		}
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
