# Example:
#
# "Ensure that ingress hostnames are whitelisted."
#
# Or more specifically, "Ensure that ingress hostnames match a whitelist entry on the containing namespace."

package kubernetes.invariants

import data.kubernetes.ingresses
import data.kubernetes.namespaces

violations[{
    "namespace": namespace,
    "name": name,
    "message": "ingress hostname must match whitelist",
}] {
    ingress := ingresses[namespace][name]
    host := ingress.spec.rules[_].host
    not contains(whitelist[namespace], host)
}

whitelist[namespace] = hosts {
    obj := namespaces[namespace]
    hosts := json.unmarshal(obj.metadata.annotations["acmecorp.com/hostname-whitelist"])
}

contains(xs, x) {
    xs[_] = x
}


## Tests

test_violations {

    bad_ingress := {
        "default": {
            "bad_ingress": {
                "spec": {
                    "rules": [
                        {
                            "host": "prod.foo.com"
                        },
                    ],
                },
            },
        },
    }

    good_ingress := {
        "default": {
            "bad_ingress": {
                "spec": {
                    "rules": [
                        {
                            "host": "dev.foo.com"
                        },
                    ],
                },
            },
        },
    }

    namespaces := {
        "default": {
            "metadata": {
                "annotations": {
                    "acmecorp.com/hostname-whitelist": `["dev.foo.com"]`,
                }
            }
        }
    }
    
    violations[x] with data.kubernetes.ingresses as bad_ingress with data.kubernetes.namespaces as namespaces
    x.namespace = "default"
    x.name = "bad_ingress"
    
    violations == set() with data.kubernetes.ingresses as good_ingress with data.kubernetes.namespaces as namespaces
}
