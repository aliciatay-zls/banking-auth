package domain

import (
	"database/sql"
	"errors"
	"github.com/jmoiron/sqlx"
	"github.com/udemy-go-1/banking-lib/errs"
	"github.com/udemy-go-1/banking-lib/logger"
)

type AuthRepository interface { //repo (secondary port)
	Authenticate(string, string) (*Auth, *errs.AppError)
	SaveRefreshTokenToStore(string) *errs.AppError
	DeleteRefreshTokenFromStore(string) *errs.AppError
	FindRefreshToken(string) (bool, *errs.AppError)
	FindUser(string, string, string) (*Auth, *errs.AppError)
	IsAccountUnderCustomer(string, string) *errs.AppError
}

type AuthRepositoryDb struct { //DB (adapter)
	client *sqlx.DB
}

func NewAuthRepositoryDb(dbClient *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{dbClient}
}

func (d AuthRepositoryDb) Authenticate(un string, pw string) (*Auth, *errs.AppError) { //DB implements repo
	var auth Auth
	err := d.client.Get(&auth, `SELECT username, password, role, customer_id FROM users WHERE username = ?`, un)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.NewAuthenticationError("Incorrect username or password")
		}
		logger.Error("Error while querying/scanning user: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}

	if !IsHashGivenPassword(auth.HashedPassword, pw) {
		return nil, errs.NewAuthenticationError("Incorrect username or password")
	}

	return &auth, nil
}

func (d AuthRepositoryDb) SaveRefreshTokenToStore(refreshToken string) *errs.AppError {
	insertTokenSql := `INSERT INTO refresh_token_store (refresh_token) VALUES (?)`
	if _, err := d.client.Exec(insertTokenSql, refreshToken); err != nil {
		logger.Error("Error while storing refresh token: " + err.Error())
		return errs.NewUnexpectedError("Unexpected database error")
	}

	return nil
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

func (d AuthRepositoryDb) FindRefreshToken(token string) (bool, *errs.AppError) {
	var isExists bool
	findTokenSql := `SELECT EXISTS(SELECT 1 FROM refresh_token_store WHERE refresh_token = ?)`
	if err := d.client.Get(&isExists, findTokenSql, token); err != nil {
		logger.Error("Error while checking if refresh token exists: " + err.Error())
		return false, errs.NewUnexpectedError("Unexpected database error")
	}

	return isExists, nil
}

func (d AuthRepositoryDb) FindUser(un string, role string, cid string) (*Auth, *errs.AppError) {
	var auth Auth
	var err error

	if cid == "" {
		findUserSql := "SELECT username, password, role, customer_id FROM users WHERE username = ? AND role = ? AND customer_id IS NULL"
		err = d.client.Get(&auth, findUserSql, un, role)
	} else {
		findUserSql := "SELECT username, password, role, customer_id FROM users WHERE username = ? AND role = ? AND customer_id = ?"
		err = d.client.Get(&auth, findUserSql, un, role, cid)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Error("User does not exist")
			return nil, errs.NewAuthenticationError("Cannot continue")
		}
		logger.Error("Error while checking if user exists: " + err.Error())
		return nil, errs.NewUnexpectedError("Unexpected database error")
	}
	return &auth, nil
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
