package authz

default allow = false

# Try to resolve permission from resource + action
resolve_permission(perm) if {
  input.request.resource
  input.request.action
  perm := sprintf("%s.%s", [input.request.resource, input.request.action])
}

# Or resolve permission from endpoint path + method
resolve_permission(perm) if {
  some moduleName
  some endpoint

  module := data.modules[moduleName]
  endpoint := module.endpoints[_]

  startswith(input.request.path, endpoint.path)
  endpoint.methods[_] == input.request.method

  perm := endpoint.permission
}

# Main allow rule:
# user.role → resolves to groups → groups contain permission
allow if {
  resolve_permission(perm)
  role := input.user.role
  group := data.roles[role][_]
  data.groups[group][_] == perm
}

# Fallback: direct permissions on user
allow if {
  resolve_permission(perm)
  input.user.permissions[_] == perm
}
