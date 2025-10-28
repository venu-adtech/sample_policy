package authz

default allow = false

# Allow if the user's group has the required permission
allow {
    some group
    input.user.groups[_] == group
    data.groups[group][_] == input.permission
}
