# Lane restart queue (pull)

After a service key is activated, the lane that holds the old key has to be
restarted. The server cannot reach that host, so the restart is a pull: the
server queues a request and a poller on the host claims it, restarts the lane
and acknowledges the result.

A request holds the lane name (from an allowlist, `Hugh` and `Test` by default),
the key version label and the `kfp1` fingerprint. It never holds a key value.

States: `pending`, `claimed`, `done`, `nothing_running`, `failed`, `expired`.
A pending request expires 15 minutes after it was queued. A claim leases a
request for 5 minutes; a lease that runs out returns it to pending. A claimed
request whose lease ran out after those 15 minutes counts as expired even if
no poller comes back, so self-rotation still reaches its outcome.

## Poller role

The poller authenticates with a service token whose scope is
`restart_poll:<org id>`. Issue it with `POST /orgs/{org_id}/tokens`
(`kind: "s"`). The role reaches only the two routes below; it holds no
permission in the secret catalog. It is not the token the Mesh plugin rotates.
Any other caller gets 403.

## Routes

`POST /v1/restarts/claim` answers 200 with up to ten requests:

```json
[{"request_id": "…", "lane": "Hugh", "key_version": "…", "fingerprint": "kfp1:…", "claim_token": "<32 hex>"}]
```

Every claim, a reissue after a lapsed lease included, returns a new
`claim_token`: 128 random bits, hex-encoded. The server keeps only its digest.
The token fences the claim: only its holder can acknowledge.

`POST /v1/restarts/{request_id}/ack` takes
`{"result": "ok|nothing_running|failed", "claim_token": "…"}` and answers 204. A
repeat with the same token and result answers 204 again; another result for a
finished request answers 409; an unknown, foreign, unclaimed or expired id, a
missing or wrong token, and a stale holder after a reissue all answer 404 with
no detail.

A key counts as applied after an ack of `ok` or `nothing_running`; `failed` and
an expired request do not. The old key is ended only after an applied outcome. After
`failed` or expiry both keys stay valid and the rotation reports an orphaned
state for a person to resolve. With the queue the self-rotation asks Mesh for a
grace window of at least 1200 seconds (`mesh.RestartGraceSeconds`), longer
than any request can stay open, so the replaced ext_ token cannot die on its
own before the queue settles. While a request is open the server looks at its
outcome every minute, not once per rotation interval, so an applied, failed or
expired outcome is acted on while the old token still works.
