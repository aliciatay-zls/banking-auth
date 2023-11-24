package domain

import (
	"database/sql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/udemy-go-1/banking-lib/logger"
	"time"
)

type Auth struct { //business/domain object //currently only 2 roles
	Username   string         `db:"username"`
	Role       string         `db:"role"`
	CustomerId sql.NullString `db:"customer_id"`
}

// IsRoleValid is similar to customClaims.go#isRoleValid.
func (a *Auth) IsRoleValid() bool {
	if a.Role != RoleUser && a.Role != RoleAdmin {
		logger.Error("Auth object has unknown role")
		return false
	}
	if a.Role == RoleUser && !a.CustomerId.Valid {
		logger.Error("Auth object has user role but no customer ID")
		return false
	}
	if a.Role == RoleAdmin && a.CustomerId.Valid {
		logger.Error("Auth object has admin role but has a customer ID")
		return false
	}
	return true
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
