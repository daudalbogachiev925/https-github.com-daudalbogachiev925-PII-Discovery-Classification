from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class User:
    id: str
    roles: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)  # dept, level, location

@dataclass
class Resource:
    id: str
    classification: str  # public/internal/confidential/restricted
    domain: str
    owner: str
    attributes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Policy:
    id: str
    effect: str  # allow / deny
    actions: List[str]  # read, write, delete, export
    subjects_roles: List[str]
    resources_classification: List[str]
    conditions: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
