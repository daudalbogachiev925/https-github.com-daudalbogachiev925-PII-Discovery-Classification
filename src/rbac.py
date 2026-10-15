from src.models import Policy, User, Resource

def rbac_check(user: User, resource: Resource, action: str, policies: list):
    """Проверка по ролям."""
    for policy in sorted(policies, key=lambda p: -p.priority):
        if action not in policy.actions:
            continue
        if not any(r in policy.subjects_roles for r in user.roles):
            continue
        if resource.classification not in policy.resources_classification:
            continue
        return policy.effect == "allow", policy
    return False, None
