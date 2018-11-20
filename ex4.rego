package app.filtering

#----------------------------------------------------------------------
# Data Filtering Policy

# Enumerate the set of posts the user is allowed to see.
posts[post] {
    post := data.posts[_]

    # Users are allowed to see posts at (or below) their
    # clearance level in their own department.
    post.department = input.subject.department
    post.security_level <= input.subject.clearance_level
}

#----------------------------------------------------------------------
# API Authorization Policy

# Allow users to get specific posts.
allow {
    input.method = "GET"
    input.path = ["posts", post_id]
    posts[post]
    post.id = post_id
}

# Allow users to list posts.
allow {
    input.method = "GET"
    input.path = ["posts"]
    posts[post]
}


# Example output:
#
# data.posts[x].department = "legal"
# data.posts[x].security_level <= 3
