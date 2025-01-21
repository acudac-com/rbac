package rbac_test

import (
	"testing"
	"time"

	"github.com/acudac-com/rbac"
)

var TenantMember = &rbac.Role{Id: "Tenant Member", Permissions: []string{
	"/use.Tenants/Get",
}}
var TenantOwner = &rbac.Role{Id: "Tenant Owner", Extends: TenantMember, Permissions: []string{
	"/use.Tenants/Update",
	"/use.Tenants/Delete",
}}

func init() {
	rbac.Init(TenantMember, TenantOwner)
}

func Test_Basic(t *testing.T) {
	az := rbac.NewAz()
	az.AddRolesAsync(func() ([]string, error) {
		time.Sleep(1 * time.Second)
		return []string{"Tenant Member"}, nil
	})
	if err := az.AsyncFetchErr(); err != nil {
		t.Error(err)
	}

	if !az.HasAccess("/use.Tenants/Get") {
		t.Error("should have get permission")
	}
	if az.HasAccess("/use.Tenants/Update") {
		t.Error("should not have update permission")
	}
}
