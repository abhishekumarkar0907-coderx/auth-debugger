# Auth Engine — Deterministic Authorization Analysis

The **auth-engine** is the core security reasoning module for the Authorization
Debugger.  It determines whether a downstream service action represents a
**confused-deputy condition** — i.e., whether a service used its own broader
privileges to act on behalf of a user without legitimate delegation.

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Original Authority** | Permissions the initiating principal possesses |
| **Delegated Authority** | Permissions explicitly delegated through each hop |
| **Service Authority** | Permissions the acting service holds independently |
| **Request Authority** | The authority legitimately available to the *request* at a given hop |

> **Core Invariant**: A service's own privileges MUST NOT silently enlarge the
> authority available to the request on behalf of the original principal.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `DETECTED` | Confused-deputy condition confirmed |
| `NOT_DETECTED` | Action is legitimately authorized |
| `INSUFFICIENT_EVIDENCE` | Cannot make a determination — required data is missing |

## Usage

```python
from auth_engine.detector import ConfusedDeputyDetector
from auth_engine.models import AuthorizationScenario, ...

scenario = AuthorizationScenario(...)
detector = ConfusedDeputyDetector()
result = detector.analyze(scenario)
print(result.verdict, result.reason)
```

## Testing

```bash
cd auth-engine
pip install -e ".[dev]"
pytest -v
```
