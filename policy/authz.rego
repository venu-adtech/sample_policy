package authz

default allow = false

# Allow admin users to access any endpoint
allow {
    input.user.role == "admin"
}

# Allow users to access their own data
allow {
    input.path == "/location/my/start"
    input.user.id == input.resource_id
}

# Define permissions for different roles
allow {
    input.user.role == "employee"
    allowed_paths_for_managers[input.path]
}

# Define allowed paths for managers
allowed_paths_for_managers = {
    "/getAllEmployee",
    "/getEmployeeStats",
    "/getCurrentLocation"
}
