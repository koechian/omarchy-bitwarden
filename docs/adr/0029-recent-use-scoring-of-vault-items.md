# ADR 0029: Recent-Use Scoring of Vault Items

## Status
Accepted. Builds on [ADR 0027](0027-redacted-item-access-and-per-field-secret-release.md) (redacted items, per-field release) and [ADR 0028](0028-paste-sequence-through-a-native-data-control-source.md) (paste sequences). The wire contract is in [contracts.md section 3.7](../agents/contracts.md#37-recent-use-adr-0029); the item fields are in [section 3.2](../agents/contracts.md#32-redacted-item).

## Context
The bar dropdown and the overlay show a "Recent" collection: the logins a user copies often and lately come first. Ranking needs a record of uses that survives daemon restarts and locks, and a score that weighs frequency against recency. The UI must not compute or store this itself: it cannot observe releases reliably (the CLI and other callers release too), and keeping the record in one place keeps its retention and privacy rules in one place.

## Decision

### 1. The daemon records uses
A use is a successful `copy_field` (one per request) or a successful `copy_sequence` (one per sequence, not one per stage), recorded only after the clipboard write succeeded or the sequence started. `reveal_field` is viewing, not using, and is not recorded; neither are `copy` (caller-supplied text with no item id), refused requests or refunded releases.

### 2. Exponentially decayed frequency
`usage_score(item, now) = Σ 0.5 ^ ((now − t) / USAGE_HALF_LIFE)` over the item's kept timestamps, with `USAGE_HALF_LIFE` = 7 days. Each use contributes 1 when it happens and halves every week, so ten uses last month and one use this morning compare sensibly without tuning buckets. At most `USAGE_TIMESTAMPS_PER_ITEM` (20) timestamps are kept per item, and timestamps older than `USAGE_RETENTION` (90 days, about 13 half-lives, where a use weighs under 0.0002) are dropped on every write and on load. The score is computed when an item view is built and rounded to 3 decimals.

### 3. Storage and lifecycle
The record is `usage.json` next to `data.json` (same directory, `0700`), mode `0600`, written through the engine's atomic write. It holds `{"version": 1, "items": {"<item id>": [<Unix seconds>, …]}}` and nothing else: no names, URIs or secret values. The daemon loads it at start and keeps it in memory behind a mutex. A successful sync drops items no longer in the vault (cipher ids of the synced cache). Locks keep the record, since they do not change who the user is. Logout and a server change delete it: logout asks the daemon to forget its table (`clear_item_usage`) and removes the file itself in case no daemon answers. A read or write failure is logged as a warning; it never fails the copy that caused the use.

### 4. Interface
Every redacted item (`list`, `search`, `get_item`) carries `usage_score` (number, 0 when never used) and `last_used_at` (RFC 3339 UTC or null). The UI sorts and filters; there is no separate command.

## Alternatives Considered
- **Counting uses in fixed windows** (last day, last week): needs bucket weights and produces jumps when a use crosses a boundary; the decayed sum is continuous and has one parameter.
- **Storing only a count and a last-use time per item**: cannot decay older uses individually, so an item used heavily months ago outranks one used daily this week.
- **Recording in the overlay**: misses uses made through the CLI and spreads the retention rules across two codebases.
- **Recording `reveal_field`**: viewing a secret is not the action the collection is meant to shortcut, and it would rank items by inspection rather than by use.

## Consequences
- **Positive**: one place records and scores uses; the UI reads two non-secret fields; the record is small (at most 20 integers per used item) and expires on its own.
- **Privacy**: the file shows which item ids were copied and when, readable only by the user. It reveals no vault content, but it is a usage history, which is why it is bounded to 90 days and deleted on logout.
- **Clock changes**: timestamps are wall-clock seconds. A use stamped in the future after the clock moved back counts as a use made now until the clock passes it.
- **Concurrent writers**: only the daemon writes the record while it runs; a sync made without the daemon prunes the file directly.
- **Versioning**: the engine that implements this ADR is 0.14.0.
