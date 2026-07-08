from .permissions import PERMISSIONS

ROLES = {

    "viewer": {
        "decision.read",
        "audit.read",
        "profile.read",
    },

    "developer": {
        "decision.read",
        "decision.write",
        "runtime.execute",
        "profile.read",
        "profile.write",
    },

    "auditor": {
        "decision.read",
        "audit.read",
        "audit.export",
        "profile.read",
    },

    "security_admin": {
        "decision.read",
        "decision.write",
        "runtime.execute",
        "policy.read",
        "policy.write",
        "audit.read",
        "audit.export",
        "profile.read",
        "profile.write",
    },

    "owner": set(PERMISSIONS),

}
