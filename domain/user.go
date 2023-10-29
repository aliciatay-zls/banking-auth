package domain

import (
	"database/sql"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type User struct { //business/domain object //currently only 2 roles //to check when writing create account api
	Username   string         `db:"username"`
	Role       string         `db:"role"`
	CustomerId sql.NullString `db:"customer_id"`
}

func (u *User) AsAccessTokenClaims() AccessTokenClaims {
	if u.CustomerId.Valid {
		return u.userClaims()
	} else {
		return u.adminClaims()
	}
}

func (u *User) userClaims() AccessTokenClaims {
	return AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
		},
		Username:   u.Username,
		Role:       u.Role,
		CustomerId: u.CustomerId.String,
	}
}

func (u *User) adminClaims() AccessTokenClaims {
	return AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
		},
		Username: u.Username,
		Role:     u.Role,
	}
}
