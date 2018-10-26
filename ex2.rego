# Employees can see their own salary and the salaries of people who report to them.
package acmecorp.authz

allow {
    input.method = "GET"
    input.path = ["salaries", employee_id]
    input.user = employee_id
}

allow {
    input.method = "GET"
    input.path = ["salaries", employee_id]
    input.user = data.manager_of[employee_id]
}