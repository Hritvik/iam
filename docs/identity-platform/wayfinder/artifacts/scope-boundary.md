# Scope Boundary: Identity Platform Foundation through Dutch Onboarding

## Work Item

This planning run descends from the operator's request in this conversation to proceed with the recommended next step after completing the shared Identity Platform Wayfinder: create the Foundation-through-Slice-C implementation plan in the dedicated IAM repository, then use that plan to bootstrap implementation through TDD.

## Stated Scope

> "The immediate next task should be an implementation plan and work-item breakdown for Foundation through Slice C. That work can proceed without prematurely choosing cloud services."

The operator answered:

> "sounds good"

and then:

> "proceed"

## Stated Exclusions

Cloud-provider, region, managed-service topology, IAM database physical-isolation, and recurring-cost decisions remain with the separately owned cloud-solutions session and the open `Reconcile the cloud solution with Identity Platform requirements` ticket.

This run does not implement Slices D–H, product-domain profiles outside Dutch UMS, Ledger, Gateway, mobile clients, Midas, Jarvis, or cloud infrastructure. It does not commit or push.

## Operator-Stated Scope

The operator approved the recommended sequence: establish the IAM application foundation, plan Foundation through Slice C, publish contract-first artifacts, and implement the first Dutch IAM-to-UMS proving slice without choosing cloud services prematurely.

## Direction of Travel

Replace the legacy Go placeholder and the Dutch-owned IAM prototype as canonical implementations with a dedicated Java/Spring/PostgreSQL IAM platform. Preserve and deliberately port validated behavior, tests, and useful code; do not preserve obsolete repository ownership, event naming, or unused prototype schemas merely for compatibility.

## Visual Material Received

None received.

## Record Provenance

Established by `han-planning:plan-implementation` from the operator's requests and the resolved Identity Platform Wayfinder, especially `Define the implementation handoff and build sequence`.
