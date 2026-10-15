from itertools import product

def simulate_matrix(engine, users, resources, actions):
    """Матрица доступов: user × resource × action → allow/deny."""
    results = []
    for u, r, a in product(users, resources, actions):
        decision = engine.check(u, r, a)
        results.append({
            "user": u.id, "role": ",".join(u.roles),
            "resource": r.id, "classification": r.classification,
            "action": a, "allowed": decision["allowed"],
            "policy": decision["policy_id"],
        })
    return results
