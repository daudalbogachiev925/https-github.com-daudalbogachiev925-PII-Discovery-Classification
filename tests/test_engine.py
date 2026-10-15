from src.models import User, Resource, Policy
from src.policy_engine import PolicyEngine
from src.conflicts import find_conflicts

def test_admin_can_read_restricted():
    e = PolicyEngine("rbac")
    e.add_policy(Policy("p1", "allow", ["read"], ["admin"], ["restricted"], priority=1))
    u = User("u1", ["admin"])
    r = Resource("r1", "restricted", "hr", "o")
    assert e.check(u, r, "read")["allowed"] is True

def test_deny_overrides_allow():
    e = PolicyEngine("rbac")
    e.add_policy(Policy("p1", "allow", ["read"], ["analyst"], ["confidential"], priority=1))
    e.add_policy(Policy("p2", "deny", ["read"], ["analyst"], ["confidential"], priority=10))
    u = User("u1", ["analyst"])
    r = Resource("r1", "confidential", "finance", "o")
    assert e.check(u, r, "read")["allowed"] is False

def test_find_conflicts():
    policies = [
        Policy("p1", "allow", ["read"], ["analyst"], ["confidential"]),
        Policy("p2", "deny", ["read"], ["analyst"], ["confidential"]),
    ]
    assert len(find_conflicts(policies)) == 1
