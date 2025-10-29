package authz

default allow = false

#
# Resolve the permission string.
# Either from input.request.resource + input.request.action
# or by matching path + method from data.modules.
#
resolve_permission(perm) if {
  input.request.resource
  input.request.action
  perm := sprintf("%s.%s", [input.request.resource, input.request.action])
}

resolve_permission(perm) if {
  some moduleName
  some endpoint

  module := data.modules[moduleName]
  endpoint := module.endpoints[_]

  startswith(input.request.path, endpoint.path)
  endpoint.methods[_] == input.request.method

  perm := endpoint.permission
}

#
# Allow when:
# 1) User has a role → role maps to groups
# 2) Groups map to permissions
#
allow if {
  resolve_permission(perm)
  some role
  some group

  role := input.user.role           # <- expected structure input.user.role = "admin"
  data.roles[role][_] == group      # role → groups
  data.groups[group][_] == perm     # group → permissions
}

#
# Also allow for direct user → permissions
#
allow if {
  resolve_permission(perm)
  input.user.permissions[_] == perm
}
