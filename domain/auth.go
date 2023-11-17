package domain

import (
	"database/sql"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type Auth struct { //business/domain object //currently only 2 roles //to check when writing create account api
	Username   string         `db:"username"`
	Role       string         `db:"role"`
	CustomerId sql.NullString `db:"customer_id"`
}

func (a *Auth) AsAccessTokenClaims() AccessTokenClaims {
	if a.CustomerId.Valid {
		return a.userClaims()
	} else {
		return a.adminClaims()
	}
}

func (a *Auth) userClaims() AccessTokenClaims {
	return AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
		},
		Username:   a.Username,
		Role:       a.Role,
		CustomerId: a.CustomerId.String,
	}
}

func (a *Auth) adminClaims() AccessTokenClaims {
	return AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
		},
		Username: a.Username,
		Role:     a.Role,
	}
}
