package domain

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"strconv"
)

type RegistrationRepositoryDb struct { //DB (adapter)
	client *sqlx.DB
}

func NewRegistrationRepositoryDb(dbClient *sqlx.DB) RegistrationRepositoryDb {
	return RegistrationRepositoryDb{dbClient}
}

func (d RegistrationRepositoryDb) Process(reg Registration) (*Registration, *errs.AppError) {
	tx, err := d.client.Begin()
	if err != nil {
		logger.Error("Error while starting db transaction for processing registration: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	result, err := d.client.Exec("INSERT INTO customers (name, date_of_birth, email, city, zipcode, status) VALUES (?, ?, ?, ?, ?, ?)",
		reg.Name, reg.DateOfBirth, reg.Email, reg.City, reg.Zipcode, reg.Status)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Fatal("Error while rolling back creation of new customer: " + rollbackErr.Error())
		}
		logger.Error("Error while creating customer: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	newCustomerId, err := result.LastInsertId()
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Fatal("Error while rolling back creation of new customer: " + rollbackErr.Error())
		}
		logger.Error("Error while getting id of newly inserted customer: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}
	reg.Id = strconv.FormatInt(newCustomerId, 10)

	_, err = d.client.Exec("INSERT INTO users VALUES (?, ?, ?, ?, ?)",
		reg.Username, reg.Password, reg.Role, reg.Id, reg.Date)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Fatal("Error while rolling back creation of new user: " + rollbackErr.Error())
		}
		logger.Error("Error while creating user: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	// For demonstration purposes: create two different accounts for the newly-registered user
	insertAccountsSql := "INSERT INTO accounts (customer_id, opening_date, account_type, amount, status) VALUES (?, ?, ?, ?, ?)"
	type accountDetails struct {
		Type   string
		Amount float64
		Status string
	}
	ad := []accountDetails{
		{"saving", 30000, "1"},
		{"checking", 6000, "1"},
	}
	for k, v := range ad {
		result, err = d.client.Exec(insertAccountsSql, reg.Id, reg.Date, v.Type, v.Amount, v.Status)
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				logger.Fatal(fmt.Sprintf("Error while rolling back creation of new account %d: %s", k+1, err.Error()))
			}
			logger.Error(fmt.Sprintf("Error while creating new account %d: %s", k+1, err.Error()))
			return nil, errs.NewUnexpectedError("Unexpected database error")
		}
	}

	return &reg, nil
}
