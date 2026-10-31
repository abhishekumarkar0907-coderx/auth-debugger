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

## Detection coverage and limitations

| Scenario | Current behavior |
|----------|------------------|
| Unauthorized permission added during explicit delegation, without an edge-specific trusted grant | `DETECTED` as `UNAUTHORIZED_DELEGATION` |
| Required permission is present in the initiating principal's delegated request authority | `NOT_DETECTED` |
| Initiating principal or required evidence is missing | `INSUFFICIENT_EVIDENCE` |
| Delegation edges do not connect to the initiating principal and one another | `INSUFFICIENT_EVIDENCE`; no finding is produced from a disconnected chain |
| Extracted delegation hop is missing or has conflicting source/recipient metadata | `INSUFFICIENT_EVIDENCE`; an incomplete hop is not silently discarded and treated as a direct call |
| Final delegation recipient cannot be tied to the operation service by identity evidence | `INSUFFICIENT_EVIDENCE` |
| An entirely absent delegation chain | Treated as a direct call; the model cannot determine whether intermediary hops were omitted |
| Excess permissions already held by the initiator are propagated unchanged | Not detected as excessive; this engine does not assess least-privilege scope |
| Circular delegation with no unauthorized permission expansion | No cycle finding; cycle safety is not analyzed by the detector |
| Conflicting principal identity evidence in extracted telemetry | Context extraction marks critical conflicts insufficient and refuses to build a scenario |

`NOT_DETECTED` means only that the implemented authorization checks found no
supported violation. It is not a determination that propagated authority is
least-privileged or that a delegation cycle is safe. An unauthorized permission
expansion on a cyclic path can still be detected by the explicit expansion
rule; the cycle itself is not a finding.

An empty delegation chain is currently interpreted as a direct call, so the
input cannot distinguish a verified direct call from absent, incomplete, or
unextractable delegation telemetry. A backward-compatible extension would add
optional delegation-completeness metadata (for example `verified_direct`,
`observed_chain`, `incomplete`, or `unknown`). Existing producers could omit
the field during migration; strict consumers should treat omitted/unknown
status as insufficient evidence before relying on it to rule out intermediary
delegation.

The engine also has no least-privilege baseline or observed-permission-use
field. Such a check requires an operation-specific maximum grant policy and
evidence of permissions actually exercised; authority breadth alone does not
establish misuse.

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
