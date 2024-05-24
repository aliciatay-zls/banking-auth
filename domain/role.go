package domain

import "github.com/aliciatay-zls/banking-lib/logger"

const RoleAdmin = "admin"
const RoleUser = "user"

type RolePermissions struct {
	rolePermissionsMap map[string][]string
}

func NewRolePermissions() RolePermissions {
	return RolePermissions{map[string][]string{
		RoleAdmin: {"GetAllCustomers", "GetCustomer", "GetAccountsForCustomer", "NewAccount", "NewTransaction"},
		RoleUser:  {"GetCustomer", "GetAccountsForCustomer", "NewTransaction"},
	}}
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
