package authz

default allow = false

# Allow admin users to do anything
allow {
  input.user.role == "admin"
}

# Allow regular users only for GET endpoints
allow {
  input.user.role == "user"
  input.method == "GET"
}
