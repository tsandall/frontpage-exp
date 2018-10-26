# Developers can access hosts running apps they work in certain time windows. 
package ssh.fine_grained

allow {
    certs := crypto.x509.parse_certificates(input.certificates)
    certs[i].Subject.Organization[j] == data.host_info.apps[_]
    certs[i].Subject.OrganizationalUnit[j] == "dev"
    time.now_ns() >= certs[i].NotBefore
    time.now_ns() <= certs[i].NotAfter
}