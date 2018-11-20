# Kubernetes Admission Control Invariants

package kubernetes.invariants

import data.kubernetes.ingresses
import data.kubernetes.namespaces

#----------------------------------------------------------------------
# Ingress Invariants

# Generates a list of ingresses (identified by `namespace` and `name`)
# that contain invalid hosts.
violations[{
    "namespace": namespace,
    "name": name,
    "message": "ingress hostname must match whitelist",
}] {
    ingress := ingresses[namespace][name]
    host := ingress.spec.rules[_].host
    not contains(whitelist[namespace], host)
}

# Generates a list of allowed hostnames per namespace.
whitelist[namespace] = hosts {
    obj := namespaces[namespace]
    annotations := obj.metadata.annotations
    annotation := annotations["acmecorp.com/hostname-whitelist"]
    hosts := json.unmarshal(annotation)
}

#----------------------------------------------------------------------
# Helpers

# Checks if `list` includes an element matching `item`.
contains(list, item) {
    list[_] = item
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
