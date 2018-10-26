# Users can see posts in their department if they have sufficient clearance.
package app.filtering

posts[post] {
    post := data.posts[_]
    post.department == input.subject.department
    post.security_level <= input.subject.clearance_level
}

allow {
    input.method = "GET"
    input.path = ["posts", post_id]
    posts[post]
    post.id = post_id
}

allow {
    input.method = "GET"
    input.path = ["posts"]
    posts[post]
}

p {
    allow = true
}

# Example output:
# 
# data.posts[x].department = "legal"
# data.posts[x].security_level <= 3
