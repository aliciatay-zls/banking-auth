package domain

import (
	"database/sql"
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"strconv"
)

type RegistrationRepository interface { //repo (secondary port)
	Save(Registration) *errs.AppError
	IsEmailRegistered(string) *errs.AppError
	IsEmailTaken(string) *errs.AppError
	IsUsernameTaken(string) *errs.AppError
	Confirm(Registration, string) (*Registration, *errs.AppError)
}

type RegistrationRepositoryDb struct { //DB (adapter)
	client *sqlx.DB
}

func NewRegistrationRepositoryDb(dbClient *sqlx.DB) RegistrationRepositoryDb {
	return RegistrationRepositoryDb{dbClient}
}

// Save uses the given Registration to check whether any of the following cases are true:
//
// 1) the given email was already used to register for an app account
//
// 2) there is already a User with the given username, or
//
// 3) there is already a Customer with the given email.
//
// If so, the Registration is rejected, otherwise it is saved to the db.
func (d RegistrationRepositoryDb) Save(reg Registration) *errs.AppError {
	if appErr := d.IsEmailRegistered(reg.Email); appErr != nil {
		return appErr
	}
	if appErr := d.IsEmailTaken(reg.Email); appErr != nil {
		return appErr
	}
	if appErr := d.IsUsernameTaken(reg.Username); appErr != nil {
		return appErr
	}

	_, err := d.client.Exec(`INSERT INTO registrations 
    (email, name, date_of_birth, city, zipcode, username, password, role, requested_on) VALUES (?,?,?,?,?,?,?,?,?)`,
		reg.Email, reg.Name, reg.DateOfBirth, reg.City, reg.Zipcode, reg.Username, reg.Password, reg.Role, reg.DateRequested)
	if err != nil {
		logger.Error("Error while saving registration: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}
	return nil
}

// IsEmailRegistered queries the db for a Registration using the given email, and if it exists,
// checks whether it has already been confirmed.
func (d RegistrationRepositoryDb) IsEmailRegistered(email string) *errs.AppError {
	var isExists bool
	findSql := "SELECT EXISTS(SELECT 1 FROM registrations WHERE email = ?)"
	if err := d.client.Get(&isExists, findSql, email); err != nil {
		logger.Error("Error while checking if registration already exists: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}

	if isExists {
		logger.Error("Registration already exists")
		errMsg := "Email is already registered for an account"

		var confirmDate sql.NullString
		checkSql := "SELECT confirmed_on FROM registrations WHERE email = ?"
		if err := d.client.Get(&confirmDate, checkSql, email); err != nil {
			logger.Error("Error while checking if registration has been confirmed: " + err.Error())
			return errs.NewUnexpectedError("Unexpected database error")
		}
		if confirmDate.Valid { //confirmation date is not null
			return errs.NewAuthorizationError(errMsg + " and already confirmed")
		} else {
			return errs.NewAuthorizationError(errMsg + " but not confirmed")
		}
	}

	return nil //can proceed
}

// IsEmailTaken queries the db for a Customer with the given email.
func (d RegistrationRepositoryDb) IsEmailTaken(email string) *errs.AppError {
	var isExists bool
	findSql := "SELECT EXISTS(SELECT 1 FROM customers WHERE email = ?)"
	if err := d.client.Get(&isExists, findSql, email); err != nil {
		logger.Error("Error while checking if customer already exists: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}

	if isExists {
		logger.Error("Customer already exists")
		return errs.NewAuthorizationError("Email is already used")
	}

	return nil //can proceed
}

// IsUsernameTaken queries the db for a User with the given username.
func (d RegistrationRepositoryDb) IsUsernameTaken(un string) *errs.AppError {
	var isExists bool
	findSql := "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)"
	if err := d.client.Get(&isExists, findSql, un); err != nil {
		logger.Error("Error while checking if user already exists: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}

	if isExists {
		logger.Error("User already exists")
		return errs.NewAuthorizationError("Username is already taken")
	}

	return nil //can proceed
}

// Confirm creates a Customer and a User based on the given Registration. For demonstration purposes, it also
// creates two different accounts for the newly-registered user. It then fills the remaining fields of the
// Registration using the given confirmation date and data returned by the db to indicate that it has been confirmed,
// and returns the finalized Registration instance.
func (d RegistrationRepositoryDb) Confirm(reg Registration, confirmDate string) (*Registration, *errs.AppError) {
	tx, err := d.client.Begin()
	if err != nil {
		logger.Error("Error while starting db transaction for confirming registration: " + err.Error())
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
			logger.Fatal("Error while rolling back creation of new customer after trying to get id: " + rollbackErr.Error())
		}
		logger.Error("Error while getting id of newly inserted customer: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	_, err = d.client.Exec("INSERT INTO users VALUES (?, ?, ?, ?, ?)",
		reg.Username, reg.Password, reg.Role, reg.Id, confirmDate)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Fatal("Error while rolling back creation of new user: " + rollbackErr.Error())
		}
		logger.Error("Error while creating user: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	// For demonstration purposes
	insertAccountsSql := "INSERT INTO accounts (customer_id, opening_date, account_type, amount, status) VALUES (?, ?, ?, ?, ?)"
	newAccounts := []struct {
		Type   string
		Amount float64
		Status string
	}{
		{"saving", 30000, "1"},
		{"checking", 6000, "1"},
	}
	for k, v := range newAccounts {
		result, err = d.client.Exec(insertAccountsSql, reg.Id, confirmDate, v.Type, v.Amount, v.Status)
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				logger.Fatal(fmt.Sprintf("Error while rolling back creation of new account %d: %s", k+1, err.Error()))
			}
			logger.Error(fmt.Sprintf("Error while creating new account %d: %s", k+1, err.Error()))
			return nil, errs.NewUnexpectedError("Unexpected database error")
		}
	}

	id := strconv.FormatInt(newCustomerId, 10)
	reg.Confirm(id, confirmDate)

	return &reg, nil
}
