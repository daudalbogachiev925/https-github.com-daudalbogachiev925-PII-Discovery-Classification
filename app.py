import streamlit as st
import pandas as pd
from src.models import User, Resource, Policy
from src.policy_engine import PolicyEngine
from src.conflicts import find_conflicts
from src.simulator import simulate_matrix

st.set_page_config(page_title="Access Control", layout="wide")
st.title("🛡️ Access Control Policies (ABAC/RBAC)")

engine = PolicyEngine(mode="abac")

# Политики
engine.add_policy(Policy("p1", "allow", ["read"], ["analyst", "scientist"],
                         ["public", "internal"], priority=1))
engine.add_policy(Policy("p2", "allow", ["read"], ["analyst"],
                         ["confidential"],
                         conditions={"key": "dept", "op": "eq", "value": "finance"},
                         priority=5))
engine.add_policy(Policy("p3", "deny", ["export"], ["analyst", "scientist"],
                         ["confidential", "restricted"], priority=10))
engine.add_policy(Policy("p4", "allow", ["read", "write"], ["admin"],
                         ["public", "internal", "confidential", "restricted"],
                         priority=20))
engine.add_policy(Policy("p5", "deny", ["read"], ["analyst"],
                         ["restricted"], priority=15))

# Users & Resources
users = [
    User("u1", ["analyst"], {"dept": "finance"}),
    User("u2", ["analyst"], {"dept": "hr"}),
    User("u3", ["scientist"], {"dept": "r&d"}),
    User("u4", ["admin"], {"dept": "it"}),
]
resources = [
    Resource("r1", "public", "marketing", "team_a"),
    Resource("r2", "internal", "product", "team_b"),
    Resource("r3", "confidential", "finance", "team_c"),
    Resource("r4", "restricted", "hr", "team_d"),
]

tab1, tab2, tab3 = st.tabs(["🔎 Проверка", "📊 Матрица", "⚠️ Конфликты"])

with tab1:
    user_id = st.selectbox("User", [u.id for u in users])
    resource_id = st.selectbox("Resource", [r.id for r in resources])
    action = st.selectbox("Action", ["read", "write", "delete", "export"])
    u = next(u for u in users if u.id == user_id)
    r = next(r for r in resources if r.id == resource_id)
    decision = engine.check(u, r, action)
    if decision["allowed"]:
        st.success(f"✅ ALLOW (policy: {decision['policy_id']})")
    else:
        st.error(f"❌ DENY (policy: {decision['policy_id']})")

    with st.expander("Explain"):
        st.json(engine.explain(u, r, action))

with tab2:
    matrix = simulate_matrix(engine, users, resources, ["read", "write", "export"])
    df = pd.DataFrame(matrix)
    st.dataframe(df)
    st.bar_chart(df.groupby("action")["allowed"].mean())

with tab3:
    conflicts = find_conflicts(engine.policies)
    if conflicts:
        st.warning(f"Найдено конфликтов: {len(conflicts)}")
        st.dataframe(pd.DataFrame(conflicts))
    else:
        st.success("Конфликтов не найдено")
