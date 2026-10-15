def find_conflicts(policies):
    """Найти противоречия: allow vs deny для одинаковых условий."""
    conflicts = []
    for i, p1 in enumerate(policies):
        for p2 in policies[i+1:]:
            if p1.effect == p2.effect:
                continue
            # одинаковые роли и classification
            if (set(p1.subjects_roles) & set(p2.subjects_roles) and
                set(p1.resources_classification) & set(p2.resources_classification) and
                set(p1.actions) & set(p2.actions)):
                conflicts.append({
                    "policy_a": p1.id, "policy_b": p2.id,
                    "effect_a": p1.effect, "effect_b": p2.effect,
                    "overlap_roles": list(set(p1.subjects_roles) & set(p2.subjects_roles)),
                    "overlap_actions": list(set(p1.actions) & set(p2.actions)),
                    "winner": p1.id if p1.priority > p2.priority else
                              p2.id if p2.priority > p1.priority else "AMBIGUOUS",
                })
    return conflicts
