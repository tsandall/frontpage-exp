# Fine-grained SSH Authorization
package ssh.fine_grained

# Allow users in the "dev" organization to SSH into hosts if they
# possess a certificate proving they are assigned to an application
# running on the host.
allow {

    # Extract the X.509 certificate provided in the policy query.
    certs := crypto.x509.parse_certificates(input.certificates)

    # Check the user is part of the "dev" organization for an app
    # running on this host.
    certs[i].Subject.Organization[j] == data.host_info.apps[_]
    certs[i].Subject.OrganizationalUnit[j] == "dev"

    # Check the certificate's validity period at the time of login.
    time.now_ns() >= certs[i].NotBefore
    time.now_ns() <= certs[i].NotAfter
}
