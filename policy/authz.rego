package authz

default allow = false

#
# STEP 1: Resolve the canonical permission string "module.action"
#
resolve_permission(perm) {
  input.request.resource
  input.request.action
  perm = sprintf("%s.%s", [input.request.resource, input.request.action])
}

resolve_permission(perm) {
  some moduleName
  some endpoint
  data.modules[moduleName]
  endpoint = data.modules[moduleName].endpoints[_]
  startswith(input.request.path, endpoint.path)
  contains(endpoint.methods, input.request.method)
  perm = endpoint.permission
}

#
# STEP 2: Check permissions granted through Roles → Groups → Permissions
#
allow {
  resolve_permission(perm)

  # user has role r
  some r
  input.user.roles[_] == r

  # role grants groups
  some g
  data.roles[r][_] == g

  # group contains permission perm
  data.groups[g][_] == perm
}

#
# STEP 3: Fallback: user has direct permissions (user-specific overrides)
#
allow {
  resolve_permission(perm)
  input.user.permissions[_] == perm
}
