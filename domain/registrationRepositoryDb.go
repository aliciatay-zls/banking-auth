package domain

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
	"strconv"
)

type RegistrationRepository interface { //repo (secondary port)
	IsEmailUsed(string) *errs.AppError
	IsUsernameTaken(string) *errs.AppError
	Save(Registration) *errs.AppError
	UpdateLastEmailedInfo(Registration, string) *errs.AppError
	FindFromLoginDetails(string, string) (*Registration, *errs.AppError)
	FindFromEmail(string) (*Registration, *errs.AppError)
	CreateNecessaryAccounts(*Registration, string) (string, *errs.AppError)
	Update(*Registration) *errs.AppError
}

type RegistrationRepositoryDb struct { //DB (adapter)
	client *sqlx.DB
}

func NewRegistrationRepositoryDb(dbClient *sqlx.DB) RegistrationRepositoryDb {
	return RegistrationRepositoryDb{dbClient}
}

// IsEmailUsed queries the db if there is a Customer who already has the given email or a Registration made using this
// email (and whether it has already been confirmed). This is to prevent multiple registrations from using the same email.
func (d RegistrationRepositoryDb) IsEmailUsed(email string) *errs.AppError {
	var isExists bool

	findCustomersSql := "SELECT EXISTS(SELECT 1 FROM customers WHERE email = ?)"
	if err := d.client.Get(&isExists, findCustomersSql, email); err != nil {
		logger.Error("Error while checking if customer with given email already exists: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}
	if isExists {
		logger.Error("Customer with given email already exists")
		return errs.NewAuthorizationError("Email is already used")
	}

	findRegistrationsSql := "SELECT EXISTS(SELECT 1 FROM registrations WHERE email = ?)"
	if err := d.client.Get(&isExists, findRegistrationsSql, email); err != nil {
		logger.Error("Error while checking if registration with given email already exists: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}
	if isExists {
		logger.Error("Registration with given email already exists")
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

// IsUsernameTaken queries the db for a User who already has the given username or a Registration already made using
// this username. This is to prevent multiple clients from taking the same username during sign-up.
func (d RegistrationRepositoryDb) IsUsernameTaken(un string) *errs.AppError {
	var isExists bool
	findSql := `SELECT EXISTS(
		(SELECT 1 FROM users WHERE username = ?) 
		UNION 
		(SELECT 1 FROM registrations WHERE username = ?)
	)`
	if err := d.client.Get(&isExists, findSql, un, un); err != nil {
		logger.Error("Error while checking if username is taken: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}

	if isExists {
		logger.Error("User or registration with given username already exists")
		return errs.NewConflictError("Username is already taken")
	}

	return nil //can proceed
}

// Save stores the given Registration in the db.
func (d RegistrationRepositoryDb) Save(reg Registration) *errs.AppError {
	_, err := d.client.Exec(`INSERT INTO registrations 
    (email, name, date_of_birth, country, zipcode, username, password, role, created_on) VALUES (?,?,?,?,?,?,?,?,?)`,
		reg.Email, reg.Name, reg.DateOfBirth, reg.Country, reg.Zipcode, reg.Username, reg.Password, reg.Role, reg.DateRegistered)
	if err != nil {
		logger.Error("Error while saving registration: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}
	return nil
}

// UpdateLastEmailedInfo increments the number of times a confirmation link has been sent to the email in the given
// Registration, and updates the last send time using the given time string. This indicates a new link has been sent.
func (d RegistrationRepositoryDb) UpdateLastEmailedInfo(reg Registration, timeStr string) *errs.AppError {
	var numEmailAttempts int
	getSql := "SELECT email_attempts FROM registrations WHERE email = ?"
	if err := d.client.Get(&numEmailAttempts, getSql, reg.Email); err != nil {
		logger.Error("Error while getting previous number of email attempts: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}

	updateSql := "UPDATE registrations SET email_attempts = ?, last_emailed_on = ? WHERE email = ?"
	if _, err := d.client.Exec(updateSql, numEmailAttempts+1, timeStr, reg.Email); err != nil {
		logger.Error("Error while updating last emailed information for a registration: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}
	return nil
}

// FindFromLoginDetails retrieves a Registration record using the given username and password. It may or may not exist
// yet during login, so a nil Registration is returned instead of an error if it does not exist.
func (d RegistrationRepositoryDb) FindFromLoginDetails(un string, pw string) (*Registration, *errs.AppError) {
	var registration Registration
	findSql := "SELECT * FROM registrations WHERE username = ? AND password = ?"
	if err := d.client.Get(&registration, findSql, un, pw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		logger.Error("Error while checking if a registration exists for the given login details: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}
	return &registration, nil
}

// FindFromEmail retrieves a Registration record using the given email. It is expected to exist, so an error is
// returned if it does not exist.
func (d RegistrationRepositoryDb) FindFromEmail(email string) (*Registration, *errs.AppError) {
	var registration Registration
	findSql := "SELECT * FROM registrations WHERE email = ?"
	if err := d.client.Get(&registration, findSql, email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Error("The given registration does not exist")
			return nil, errs.NewNotFoundError("Registration not found")
		}
		logger.Error("Error while checking if a given registration indeed exists: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	return &registration, nil
}

// CreateNecessaryAccounts creates the necessary instances for a newly-registered user based on the given Registration:
// a Customer, then, using the generated customer ID, a User and two different bank accounts (for demonstration
// purposes). It returns the customer ID.
func (d RegistrationRepositoryDb) CreateNecessaryAccounts(reg *Registration, createTime string) (string, *errs.AppError) {
	tx, err := d.client.Begin()
	if err != nil {
		logger.Error("Error while starting db transaction for creating accounts for new registration: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected database error")
	}

	result, err := tx.Exec("INSERT INTO customers (name, date_of_birth, email, country, zipcode, status) VALUES (?, ?, ?, ?, ?, ?)",
		reg.Name, reg.DateOfBirth, reg.Email, reg.Country, reg.Zipcode, reg.Status)
	if err != nil {
		logger.Error("Error while creating customer: " + err.Error())
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Error while rolling back creation of new customer: " + rollbackErr.Error())
		}
		return "", errs.NewUnexpectedError("Unexpected database error")
	}

	newCustomerId, err := result.LastInsertId()
	if err != nil {
		logger.Error("Error while getting id of newly inserted customer: " + err.Error())
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Error while rolling back creation of new customer after trying to get id: " + rollbackErr.Error())
		}
		return "", errs.NewUnexpectedError("Unexpected database error")
	}

	_, err = tx.Exec("INSERT INTO users VALUES (?, ?, ?, ?, ?)",
		reg.Username, reg.Password, reg.Role, newCustomerId, createTime)
	if err != nil {
		logger.Error("Error while creating user: " + err.Error())
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			logger.Error("Error while rolling back creation of new user: " + rollbackErr.Error())
		}
		return "", errs.NewUnexpectedError("Unexpected database error")
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
		result, err = tx.Exec(insertAccountsSql, newCustomerId, createTime, v.Type, v.Amount, v.Status)
		if err != nil {
			logger.Error(fmt.Sprintf("Error while creating new account %d: %s", k+1, err.Error()))
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				logger.Error(fmt.Sprintf("Error while rolling back creation of new account %d: %s", k+1, err.Error()))
			}
			return "", errs.NewUnexpectedError("Unexpected database error")
		}
	}

	if err = tx.Commit(); err != nil {
		logger.Error("Error while committing transaction for creating accounts for new registration: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected database error")
	}

	id := strconv.FormatInt(newCustomerId, 10)
	return id, nil
}

// Update uses the confirmed Registration to update its related records in the db.
func (d RegistrationRepositoryDb) Update(reg *Registration) *errs.AppError {
	_, err := d.client.Exec("UPDATE registrations SET customer_id = ?, status = ?, confirmed_on = ? WHERE email = ?",
		reg.CustomerId.String, reg.Status, reg.DateConfirmed.String, reg.Email)
	if err != nil {
		logger.Error("Error while updating registration to confirmed status: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}

	_, err = d.client.Exec("UPDATE customers SET status = ? WHERE customer_id = ?",
		reg.Status, reg.CustomerId.String)
	if err != nil {
		logger.Error("Error while updating customer record to confirmed status: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}
	return nil
}
