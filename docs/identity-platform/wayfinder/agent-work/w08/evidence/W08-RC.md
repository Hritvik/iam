# W08-RC evidence — independent correctness and database review

Decision: approve

Findings: review 01 (M-1 rollback only before the event write; M-2 shipping bean graph never loaded) verified fixed: a failure after the real intent append rolls back event, delivery, audit, activation and subject; the shipping Spring graph loads under the activation, app-subject and messaging flags. Remaining lows: evidence counts, no work-item-08 artifact, non-ACTIVE states cannot retain an onboarding version, discarded delivery divergence signal, 3-attempt conflict maps to a generic error.
