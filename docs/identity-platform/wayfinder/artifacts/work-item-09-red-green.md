# W-9 red/green and decision record

- Scope: IAM onboarding relay (at-least-once) and the app-scoped repair snapshot; IAM producer side only.
- Board: [`agent-work/w09`](../agent-work/w09/board.json).

## Red/green

| Packet | RED | GREEN |
|---|---|---|
| W09-A | acknowledging a failed publish broke redelivery | lease-based relay: publish before ack, lease recovery, bounded quarantine |
| W09-B | dropping the app filter let another app read rows; limit=200 returned empty | app-bound snapshot with opaque cursor, contract message and JSON shape |
| W09-C | producer flow unproven; migration counts stale | crash-before-ack redelivery, duplicate publish, restart recovery, app-scoped snapshot |

## Decisions

- Publish happens outside the state transaction; acknowledgement follows only a successful publish.
  A crash between them leaves the delivery leased and it is redelivered after expiry.
- Attempts are bounded; exhausted and non-retryable failures quarantine with fixed reason codes.
- The snapshot is keyset-paged by App Subject with an opaque cursor; the internal probe may fetch
  `limit + 1` (max 201) while HTTP stays 1–200.
- The controller authenticates a resolved workload binding: path app equality, `iam:onboarding:read`
  and the internal audience; all failures return the same non-enumerating 404 with the pinned message.
- Without a workload authenticator the controller fails closed with the non-enumerating 404 for every request.
