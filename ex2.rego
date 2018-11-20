# HTTP API Authorization
package acmecorp.authz

# Allow employees to read their own salary.
allow {
    input.method = "GET"
    input.path = ["salaries", employee_id]
    input.user = employee_id
}

# Allow employees to read the salaries of people they manage.
allow {
    input.method = "GET"
    input.path = ["salaries", employee_id]
    input.user = data.manager_of[employee_id]
}
