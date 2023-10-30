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
	DeleteRefreshTokenFromStore(string) *errs.AppError
	FindRefreshToken(string) *errs.AppError
	FindUser(string, string, string) *errs.AppError
	IsAccountUnderCustomer(string, string) *errs.AppError
}

type AuthRepositoryDb struct { //DB (adapter)
	client *sqlx.DB
}

func NewAuthRepositoryDb(dbClient *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{dbClient}
}

func (d AuthRepositoryDb) Authenticate(username string, password string) (*User, *errs.AppError) { //DB implements repo
	var user User
	getDetailsSql := `SELECT username, role, customer_id FROM users WHERE username = ? AND password = ?`
	err := d.client.Get(&user, getDetailsSql, username, password)
	if err != nil {
		logger.Error("Error while querying/scanning details of user: " + err.Error())
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.NewAuthenticationError("Incorrect username or password")
		}
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	return &user, nil
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

func (d AuthRepositoryDb) DeleteRefreshTokenFromStore(token string) *errs.AppError {
	deleteTokenSql := `DELETE FROM refresh_token_store WHERE refresh_token = ?`
	result, err := d.client.Exec(deleteTokenSql, token)
	if err != nil {
		logger.Error("Error while deleting refresh token: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}

	rowsDeleted, err := result.RowsAffected()
	if err != nil {
		logger.Error("Error while checking that there was a deletion: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}
	if rowsDeleted != 1 {
		logger.Error("Deletion failed")
		return errs.NewUnexpectedError("Failed to log out")
	}

	return nil
}

func (d AuthRepositoryDb) FindRefreshToken(token string) *errs.AppError {
	var isExists int
	findTokenSql := `SELECT 1 FROM refresh_token_store WHERE refresh_token = ?`
	if err := d.client.Get(&isExists, findTokenSql, token); err != nil {
		logger.Error("Error while checking if refresh token exists: " + err.Error())
		if errors.Is(err, sql.ErrNoRows) {
			return errs.NewAuthenticationErrorDueToRefreshToken()
		}
		return errs.NewUnexpectedError("Unexpected database error")
	}

	return nil
}

func (d AuthRepositoryDb) FindUser(un string, role string, cid string) *errs.AppError {
	var isExists int
	var err error

	if cid == "" {
		findUserSql := `SELECT 1 FROM users WHERE username = ? AND role = ? AND customer_id IS NULL`
		err = d.client.Get(&isExists, findUserSql, un, role)
	} else {
		findUserSql := `SELECT 1 FROM users WHERE username = ? AND role = ? AND customer_id = ?`
		err = d.client.Get(&isExists, findUserSql, un, role, cid)
	}
	if err != nil {
		logger.Error("Error while checking if user exists: " + err.Error())
		if errors.Is(err, sql.ErrNoRows) {
			return errs.NewAuthenticationError("User does not exist")
		}
		return errs.NewUnexpectedError("Unexpected database error")
	}

	return nil
}

func (d AuthRepositoryDb) IsAccountUnderCustomer(aid string, cid string) *errs.AppError {
	var isExists int
	checkAccountSql := `SELECT 1 FROM accounts WHERE customer_id = ? AND account_id = ?`
	if err := d.client.Get(&isExists, checkAccountSql, cid, aid); err != nil {
		logger.Error("Error while checking if account belongs to customer: " + err.Error())
		if errors.Is(err, sql.ErrNoRows) {
			return errs.NewAuthorizationError("Account does not belong to customer")
		}
		return errs.NewUnexpectedError("Unexpected database error")
	}

	return nil
}
