package domain

import "github.com/udemy-go-1/banking-lib/logger"

type RolePermissions struct {
	rolePermissionsMap map[string][]string
}

func NewRolePermissions() RolePermissions {
	rp := RolePermissions{map[string][]string{
		"admin": {"GetAllCustomers", "GetCustomer", "NewAccount", "NewTransaction"},
		"user":  {"GetCustomer", "NewTransaction"},
	}}
	return rp
}

func (p RolePermissions) IsAuthorizedFor(role string, route string) bool {
	perms, ok := p.rolePermissionsMap[role]
	if !ok {
		logger.Error("Unknown role")
		return false
	}

	for _, v := range perms {
		if route == v {
			return true
		}
	}

	logger.Error("Client does not have role privileges to access route")
	return false
}
