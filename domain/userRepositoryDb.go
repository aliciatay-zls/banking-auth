package domain

import (
	"github.com/golang-jwt/jwt/v5"
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

	getDetailsSql := `SELECT u.role, u.customer_id, GROUP_CONCAT(a.account_id) 
					FROM users u LEFT JOIN accounts a ON u.customer_id = a.customer_id 
                    WHERE u.username = ? AND u.password = ?
                    GROUP BY u.customer_id`
	row := d.client.QueryRow(getDetailsSql, username, password)

	user := User{Username: username, Password: password}
	err := row.Scan(&user.Role, &user.CustomerId, &user.AllAccountIds)
	if err != nil {
		logger.Error("Error while scanning details of user: " + err.Error())
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

func (d UserRepositoryDb) GenerateToken(user *User) (string, *errs.AppError) { //DB implements repo
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, user.AsClaims())

	secret := []byte("hmacSampleSecret") //to store elsewhere
	tokenString, err := token.SignedString(secret)
	if err != nil {
		logger.Error("Error while signing token: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected server-side error")
	}

	return tokenString, nil
}
