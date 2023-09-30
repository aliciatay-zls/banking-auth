package domain

import (
	"database/sql"
	"errors"
	"github.com/jmoiron/sqlx"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
)

type AuthRepository interface { //repo (secondary port)
	Authenticate(string, string) (*User, *errs.AppError)
	GenerateRefreshTokenAndSaveToStore(AuthToken) (string, *errs.AppError)
	FindRefreshToken(string) *errs.AppError
}

type AuthRepositoryDb struct { //DB (adapter)
	client *sqlx.DB
}

func NewAuthRepositoryDb(dbClient *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{dbClient}
}

func (d AuthRepositoryDb) Authenticate(username string, password string) (*User, *errs.AppError) { //DB implements repo
	if err := d.checkCredentials(username, password); err != nil {
		return nil, err
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

func (d AuthRepositoryDb) checkCredentials(un string, pw string) *errs.AppError {
	var isExists int
	checkCredentialsSql := "SELECT 1 FROM users WHERE username = ? AND password = ?"
	if err := d.client.Get(&isExists, checkCredentialsSql, un, pw); err != nil {
		logger.Error("Error while checking if given username and password pair exists: " + err.Error())
		if errors.Is(err, sql.ErrNoRows) {
			return errs.NewAuthenticationError("Incorrect username or password")
		}
		return errs.NewUnexpectedError("Unexpected database error")
	}

	return nil
}

func (d AuthRepositoryDb) GenerateRefreshTokenAndSaveToStore(authToken AuthToken) (string, *errs.AppError) {
	var refreshToken string
	var appErr *errs.AppError
	if refreshToken, appErr = authToken.GenerateRefreshToken(); appErr != nil {
		return "", appErr
	}

	insertTokenSql := `INSERT INTO refresh_token_store (refresh_token) VALUES (?)`
	if _, err := d.client.Exec(insertTokenSql, refreshToken); err != nil {
		logger.Error("Error while storing refresh token: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected database error")
	}

	return refreshToken, nil
}

func (d AuthRepositoryDb) FindRefreshToken(token string) *errs.AppError {
	var isExists int
	findTokenSql := `SELECT 1 FROM refresh_token_store WHERE refresh_token = ?`
	if err := d.client.Get(&isExists, findTokenSql, token); err != nil {
		logger.Error("Error while checking if refresh token exists: " + err.Error())
		if errors.Is(err, sql.ErrNoRows) {
			return errs.NewAuthenticationError("Refresh token not registered in the store")
		}
		return errs.NewUnexpectedError("Unexpected database error")
	}

	return nil
}
