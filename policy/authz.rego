package authz

default allow = false

# Resolve permission from resource + action
resolve_permission := perm if {
  input.request.resource
  input.request.action
  perm := sprintf("%s.%s", [input.request.resource, input.request.action])
}

# Resolve permission from endpoint path + method
resolve_permission := perm if {
  some moduleName

  module := data.modules[moduleName]
  ep := module.endpoints[_]

  startswith(input.request.path, ep.path)
  ep.methods[_] == input.request.method

  perm := ep.permission
}

# Role → Groups → Permissions
allow if {
  perm := resolve_permission
  role := input.user.role
  group := data.roles[role][_]
  data.groups[group][_] == perm
}

# Direct user permissions
allow if {
  perm := resolve_permission
  input.user.permissions[_] == perm
}
