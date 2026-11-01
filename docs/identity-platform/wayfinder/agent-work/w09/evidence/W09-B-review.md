# W09-B review

Decision: approve

Findings: review 01 found (B-1 high) the limit=200 probe returned an empty page, (B-2) the 404 message violated the pinned enum, (B-3) a null cursor serialized as null, and (B-5) correlation was unvalidated. All fixed: V12 accepts a 201 probe with the HTTP bound at 200, the pinned message is used, the cursor is omitted when null, and correlation IDs are validated/regenerated. Lows: cursor grammar pinned to the 24-char subject, absent-but-bound app returns an empty page, query errors need 5xx mapping when wired.
