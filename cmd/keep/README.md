# keep — the Keep CLI

A thin HTTP client for Keep Server. It has no command that shows a secret
value, and none will be added.

```
keep login [--token-file PATH]            read the token from stdin
keep list    --scope-level L --scope-id ID [--json]
keep meta    <name> --scope-level L --scope-id ID [--json]
keep version <name> --scope-level L --scope-id ID [--json]
keep create-ref <name> --scope-level L --scope-id ID --class C --type T --provider-ref REF [--description TEXT] [--json]
keep audit verify [--json]
```

Common flags: `--server URL` (or `KEEP_SERVER`), `--org ID` (or `KEEP_ORG`),
`--token-file PATH`, `--json`, `--debug`. The token comes from `KEEP_TOKEN`
or a token file that is not readable by group or other (mode 0600).

## audit verify

`keep audit verify` calls `GET /orgs/{org_id}/audit/verify` and checks the
tamper-evident hash chain of the organization's audit journal. It prints the
server's verdict, and nothing else (a field outside its documented shape is
shown as `(unexpected value)`): the journal records themselves are
never returned.

| field | meaning |
|---|---|
| `ok` | `true` when the whole chain verifies |
| `checked` | number of records walked |
| `broken_id` | id of the first broken record (only when `ok` is false) |
| `broken_position` | its 1-based position in the chain |
| `break_kind` | `hash`, `link`, `sequence` or `head` |

Exit code: `0` chain verified, `1` chain broken or the request failed, `2`
usage error. A clean chain prints:

```
ok:       true
checked:  42
```
