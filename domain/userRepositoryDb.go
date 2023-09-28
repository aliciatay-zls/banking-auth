package domain

import (
	"github.com/jmoiron/sqlx"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
)

type UserRepositoryDb struct { //DB (adapter)
	client *sqlx.DB
}

func NewUserRepositoryDb(dbClient *sqlx.DB) UserRepositoryDb {
	return UserRepositoryDb{dbClient}
}

func (d UserRepositoryDb) Authenticate(username string, password string) (*User, *errs.AppError) { //DB implements repo
	isCorrect, appErr := d.checkCredentials(username, password)
	if !isCorrect {
		return nil, appErr
	}

	var user User
	getDetailsSql := `SELECT u.username, u.role, u.customer_id, GROUP_CONCAT(a.account_id) AS account_numbers
					FROM users u LEFT JOIN accounts a ON u.customer_id = a.customer_id 
                    WHERE u.username = ? AND u.password = ?
                    GROUP BY u.customer_id`
	err := d.client.Get(&user, getDetailsSql, username, password)
	if err != nil {
		logger.Error("Error while querying/scanning details of user: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	return &user, nil
}

func (d UserRepositoryDb) checkCredentials(un string, pw string) (bool, *errs.AppError) {
	checkCredentialsSql := "SELECT 1 FROM users WHERE username = ? AND password = ?"
	rows, err := d.client.Query(checkCredentialsSql, un, pw)
	if err != nil {
		logger.Error("Error while checking given username and password: " + err.Error())
		return false, errs.NewUnexpectedError("Unexpected database error")
	}
	if !rows.Next() {
		logger.Error("User with given username or password was not found")
		return false, errs.NewAuthenticationError("Incorrect username or password")
	}

	return true, nil
}
