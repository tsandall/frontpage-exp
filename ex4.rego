# Partial Evaluation

package app.filtering

#----------------------------------------------------------------------
# Data Filtering Policy

# Allow users to see posts their own posts.
posts[post] {
    post := data.posts[_]
    post.owner = input.subject.name
}

# Allow users to see posts in their department that they have sufficient
# clearance level for.
posts[post] {
    post := data.posts[_]
    post.department = input.subject.department
    post.security_level <= input.subject.clearance_level
}

# Example output:
#
#  Conditions (1)
#  --------------
#  data.posts[x].owner = "bob"
#
#  Conditions (2)
#  --------------
#  data.posts[x].department = "ops"
#  data.posts[x].security_level <= 3
