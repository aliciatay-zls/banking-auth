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

type UserRepository interface { //repo (secondary port)
	Authenticate(string, string) (*User, *errs.AppError)
	GenerateToken(*User) (string, *errs.AppError)
}

func (u *User) AsClaims() CustomClaims {
	var claims CustomClaims

	if u.CustomerId.Valid && u.AllAccountIds.Valid { //non-admin user
		claims = CustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},

			Username:      u.Username,
			Role:          u.Role,
			CustomerId:    u.CustomerId.String,
			AllAccountIds: u.AllAccountIds.String,
		}
	} else { //admin or non-admin user with no bank accounts
		claims = CustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},

			Username: u.Username,
			Role:     u.Role,
		}
	}

	return claims
}
