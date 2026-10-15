def evaluate_condition(user, resource, condition):
    """condition: {"key": "dept", "op": "eq", "value": "finance"}"""
    key = condition.get("key")
    op = condition.get("op")
    value = condition.get("value")

    # сначала ищем в user.attributes, затем в resource.attributes
    actual = user.attributes.get(key, resource.attributes.get(key))

    if op == "eq":
        return actual == value
    if op == "ne":
        return actual != value
    if op == "in":
        return actual in value
    if op == "contains":
        return value in (actual or [])
    if op == "gte":
        try:
            return float(actual) >= float(value)
        except (TypeError, ValueError):
            return False
    if op == "lte":
        try:
            return float(actual) <= float(value)
        except (TypeError, ValueError):
            return False
    return False

def abac_check(user, resource, action, policies):
    """Проверка с условиями (ABAC)."""
    for policy in sorted(policies, key=lambda p: -p.priority):
        if action not in policy.actions:
            continue
        if not any(r in policy.subjects_roles for r in user.roles):
            continue
        if resource.classification not in policy.resources_classification:
            continue
        if policy.conditions:
            if not all(evaluate_condition(user, resource, c)
                       for c in [policy.conditions]):
                continue
        return policy.effect == "allow", policy
    return False, None
