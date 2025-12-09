package httpapi.authz

default allow = false

required_permission = sprintf("%s.%s", [input.resource, input.action])

allow {
    raw_role := input.user.roles[_]

    # Normalize input role
    user_role := upper(raw_role)
    print("User role:", user_role)

    role_perms := data.roles_permissions.roles[user_role]
    print("Role perms:", role_perms)

    perm := role_perms[_]
    print("Checking perm:", perm)

    upper(perm) == upper(required_permission)
    print("Required:", upper(required_permission))

    print("Allowed!")
}
