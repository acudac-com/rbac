package rbac_test

import "testing"

const TenantOwner string = "Tenant Owner"

func init() {
	rbac.LoadRoles(
		&rbac.Role{
			Id:          TenantOwner,
			Permissions: []string{},
			Extends:     "Tenant Member",
		},
	)

}

func Test_Basic(t *testing.T) {
	permission := "/use.Users/Get"
	az := rbac.NewAz(permission)
	az.AddRoles("role1", "role2")
	az.AddRolesAsync(func() ([]string, error) {})
	if err := az.AsyncFetchErr(); err != nil {
		return nil, err
	}

	if !az.HasAccess() {
		return nil, unauthorized
	}
}
