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

func (u User) AsClaims() jwt.MapClaims {
	var claims jwt.MapClaims

	if u.CustomerId.Valid && u.AllAccountIds.Valid { //non-admin user
		claims = jwt.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),

			"username":    u.Username,
			"role":        u.Role,
			"customer_id": u.CustomerId.String,
			"accounts":    u.AllAccountIds.String,
		}
	} else { //admin or non-admin user with no bank accounts
		claims = jwt.MapClaims{
			"exp": time.Now().Add(time.Hour).Unix(),

			"username": u.Username,
			"role":     u.Role,
		}
	}

	return claims
}
