# W08-A review

Decision: approve

Findings: review 01 found (A-1) the activation subject was not bound to the authoritative (app, identity, subject) mapping and (A-2) the Java evaluator disagreed with SQL for an app with no registered evidence. Both fixed: the function rejects any subject that is not the exact mapping, and empty evidence is `app_not_registered` in both paths. Remaining lows: subject format looser than the authoritative 24-char pattern; activation-id collision surfaces as an exception; evidence count drift.
