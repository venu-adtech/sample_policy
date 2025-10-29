package authz

default allow = false

# Resolve permission string either from provided resource/action OR by matching
# the request path+method against data.modules definitions.
resolve_permission(perm) {
  # if resource and action provided, use them
  input.request.resource
  input.request.action
  perm = sprintf("%s.%s", [input.request.resource, input.request.action])
}

resolve_permission(perm) {
  # otherwise try to resolve from modules by matching path prefix and method
  some moduleName
  some endpoint
  data.modules[moduleName]
  endpoint = data.modules[moduleName].endpoints[_]
  startswith(input.request.path, endpoint.path)
  contains(endpoint.methods, input.request.method)
  # canonical permission is module.action (we derive action from endpoint.permission string)
  perm = endpoint.permission
}

# main allow rule: user allowed if any of their groups contains the perm
allow {
  some g
  input.user.groups[_] == g
  resolve_permission(perm)
  data.groups[g][_]==perm
}

# fallback: direct permissions on the input.user.permissions array
allow {
  resolve_permission(perm)
  some p
  input.user.permissions[_] == p
  p == perm
}
