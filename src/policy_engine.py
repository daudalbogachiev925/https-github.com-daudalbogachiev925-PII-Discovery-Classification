from src.models import User, Resource, Policy
from src.rbac import rbac_check
from src.abac import abac_check

class PolicyEngine:
    def __init__(self, mode="abac"):
        self.mode = mode
        self.policies = []

    def add_policy(self, policy: Policy):
        self.policies.append(policy)

    def check(self, user: User, resource: Resource, action: str):
        if self.mode == "rbac":
            allowed, policy = rbac_check(user, resource, action, self.policies)
        else:
            allowed, policy = abac_check(user, resource, action, self.policies)
        return {
            "allowed": allowed,
            "policy_id": policy.id if policy else None,
            "mode": self.mode,
            "action": action,
            "user": user.id,
            "resource": resource.id,
        }

    def explain(self, user, resource, action):
        reasons = []
        for p in self.policies:
            matched_action = action in p.actions
            matched_role = any(r in p.subjects_roles for r in user.roles)
            matched_class = resource.classification in p.resources_classification
            reasons.append({
                "policy": p.id, "effect": p.effect,
                "action_match": matched_action,
                "role_match": matched_role,
                "class_match": matched_class,
                "priority": p.priority,
                "would_apply": matched_action and matched_role and matched_class,
            })
        return reasons
