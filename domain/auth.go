package domain

import (
	"database/sql"
	"fmt"
	"github.com/aliciatay-zls/banking-lib/errs"
	"github.com/aliciatay-zls/banking-lib/logger"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type Auth struct { //business/domain object //currently only 2 roles
	Username       string         `db:"username"`
	HashedPassword string         `db:"password"`
	Role           string         `db:"role"`
	CustomerId     sql.NullString `db:"customer_id"`
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

// GetHomepage returns the frontend route based on the client's role
func (a *Auth) GetHomepage() (string, *errs.AppError) {
	if a.Role == "admin" {
		return "/customers", nil
	} else if a.Role == "user" && a.CustomerId.Valid && a.CustomerId.String != "" {
		return fmt.Sprintf("/customers/%s", a.CustomerId.String), nil
	} else {
		logger.Error("Unknown role or no customer ID")
		return "", errs.NewUnexpectedError("Unexpected server-side error")
	}
}
