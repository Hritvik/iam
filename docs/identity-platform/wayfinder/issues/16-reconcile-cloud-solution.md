Type: task
Status: open
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 13, 15, external cloud-solutions session

# Reconcile the cloud solution with Identity Platform requirements

## Question

When the separately owned cloud-solutions design is available, does its provider, region, topology, database isolation, messaging, cache, key custody, backup, observability, recovery, and cost model satisfy the fixed operational acceptance constraints—and what exact provider bindings complete the infrastructure implementation handoff?

## Completion checklist

- Link the authoritative cloud decision artifact and record its owner/date/status.
- Map every item in the cloud-design reconciliation gate from `Design operations, resilience, abuse controls, and key management` to a concrete service/topology/configuration decision.
- Resolve the dedicated-versus-shared production IAM database boundary and document blast radius, recurring cost, and extraction triggers.
- Demonstrate feasibility of availability, RPO/RTO, key non-exportability/rotation, environment isolation, event ordering/DLQ/replay, privacy-export retention, telemetry privacy, incident access, and budget controls.
- Identify and resolve contradictions with the Identity Platform design; do not silently inherit an older Dutch ADR.
- Add the final provider-specific infrastructure slice, tests, runbooks, and production evidence requirements to the implementation handoff.
- Clear the corresponding `Not yet specified` entry from the map and close this ticket only when no placeholder remains.
