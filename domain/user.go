package domain

import (
	"database/sql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/errs"
	"time"
)

type User struct { //business/domain object
	Username      string         `db:"username"`
	Role          string         `db:"role"`
	CustomerId    sql.NullString `db:"customer_id"`
	AllAccountIds sql.NullString `db:"account_numbers"`
}

func (u *User) AsClaims() CustomClaims {
	if u.CustomerId.Valid && u.AllAccountIds.Valid { //non-admin user
		return u.userClaims()
	} else { //admin or non-admin user with no bank accounts
		return u.adminClaims()
	}
}

func (u *User) userClaims() CustomClaims {
	return CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
		},
		Username:      u.Username,
		Role:          u.Role,
		CustomerId:    u.CustomerId.String,
		AllAccountIds: u.AllAccountIds.String,
	}
}

func (u *User) adminClaims() CustomClaims {
	return CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
		},
		Username: u.Username,
		Role:     u.Role,
	}
}

type UserRepository interface { //repo (secondary port)
	Authenticate(string, string) (*User, *errs.AppError)
	GenerateRefreshTokenAndSaveToStore(AuthToken) (string, *errs.AppError)
}
