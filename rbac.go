package rbac

import (
	"fmt"
	"sync"
)

// A role that gives some entity a list of permissions
type Role struct {
	// The unique id of the role.
	Id string
	// The list of permissions the role gives.
	Permissions []string
	// The id of another role from which permissions are inherrited by this role.
	Extends *Role
	// The type of resource where this role can be stored.
	// e.g. User or Store.
	ResourceType string
}

// Internal map for quick lookup of which roles will give the provided permission.
var permissionToRoles = map[string][]string{}
var resourceTypeToRoles = map[string]map[string]bool{}

// Call at init. Sets the roles from which access checks will be done.
func Init(roles ...*Role) error {
	// ensure there are no duplicate ids
	rolesMap := map[string]*Role{}
	for _, role := range roles {
		if _, ok := rolesMap[role.Id]; ok {
			return fmt.Errorf("found duplicate role: %s", role.Id)
		}
		rolesMap[role.Id] = role
	}

	// load resource type to roles
	for _, role := range roles {
		if role.ResourceType != "" {
			if _, ok := resourceTypeToRoles[role.ResourceType]; !ok {
				resourceTypeToRoles[role.ResourceType] = map[string]bool{}
			}
			resourceTypeToRoles[role.ResourceType][role.Id] = true
		}
	}

	// calculate which roles give which permissions
	flattenedPermissions := map[string][]string{}
	for _, role := range roles {
		permissions := role.Permissions
		if role.Extends != nil {
			if _, ok := flattenedPermissions[role.Extends.Id]; !ok {
				return fmt.Errorf("%s extends a role (%s), which has not yet appeared in the list of roles to load", role.Id, role.Extends.Id)
			}
			permissions = append(permissions, flattenedPermissions[role.Extends.Id]...)
		}
		flattenedPermissions[role.Id] = permissions
		for _, permission := range permissions {
			currentRoles := permissionToRoles[permission]
			permissionToRoles[permission] = append(currentRoles, role.Id)
		}
	}

	return nil
}

// An authorizer that can be used for access checks.
type Authorizer struct {
	// Added roles.
	roles sync.Map
	// A wait group for any async role additions.
	wg sync.WaitGroup
	// Any errors that occurred during async role additions.
	asyncErrors sync.Map
}

// Returns an authorizer to use for access checks.
func NewAz() *Authorizer {
	return &Authorizer{
		roles:       sync.Map{},
		wg:          sync.WaitGroup{},
		asyncErrors: sync.Map{},
	}
}

// Adds ids of the roles the requester has.
// Saved for all subsequent access checks.
func (a *Authorizer) AddRoles(roles ...string) {
	for _, role := range roles {
		a.roles.Store(role, true)
	}
}

// Asynchronously adds ids of the roles the requester has.
// Saved for all subsequent access checks.
func (a *Authorizer) AddRolesAsync(f func() ([]string, error)) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		roles, err := f()
		if err != nil {
			a.asyncErrors.Store(err.Error(), true)
		}
		a.AddRoles(roles...)
	}()
}

// Returns a combined error of all the async fetch errors that occurred if any.
func (a *Authorizer) AsyncFetchErr() error {
	a.wg.Wait()
	errors := []string{}
	a.asyncErrors.Range(func(key, value interface{}) bool {
		errors = append(errors, key.(string))
		return true
	})
	if len(errors) == 0 {
		return nil
	}
	return fmt.Errorf("async fetch errors: %v", errors)
}

// Returns whether the user has access to the specified permission.
func (a *Authorizer) HasAccess(permission string) bool {
	a.wg.Wait()
	rolesThatGiveAccess := permissionToRoles[permission]
	for _, role := range rolesThatGiveAccess {
		if _, ok := a.roles.Load(role); ok {
			return true
		}
	}
	return false
}

// Returns whether the specified role is allowed for the given resource
func ValidRoleForResourceType(role string, resourceType string) bool {
	if _, ok := resourceTypeToRoles[resourceType]; !ok {
		return false
	}
	if _, ok := resourceTypeToRoles[resourceType][role]; !ok {
		return false
	}
	return true
}
