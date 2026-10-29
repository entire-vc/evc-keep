#!/bin/sh
# Proves the internal/mcp guards can fail: in a scratch copy of the tree,
# switch off one property at a time and require `go test ./internal/mcp/` to go
# red. A property whose removal leaves the tests green is not tested. Exits 0
# only if every mutation is caught and the real code is green.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
. "$root/scripts/mutation-helpers.sh"
. "$root/scripts/lib/gocache.sh"
test -f "$root/go.mod" || { echo "refuse: \$root does not look like the repo root ($root)" >&2; exit 2; }
. "$root/scripts/temp-workspace.sh"
temp_workspace
pkg=internal/mcp

fail=0
# mutate NAME FILE FROM TO [N]: replace the Nth (default first) literal
# occurrence of FROM with TO in FILE.
mutate() {
	name=$1 src=$pkg/$2 from=$3 to=$4 nth=${5:-1}
	rm -rf "$work/tree"
	# Apply-only writes just the mutated file: no need to copy the whole tree.
	if mutation_apply_only; then mkdir -p "$work/tree/$pkg"; else mutation_snapshot "$work/tree"; fi
	if ! awk -v from="$from" -v to="$to" -v nth="$nth" '
		!done && (i = index($0, from)) && ++seen == nth { $0 = substr($0, 1, i-1) to substr($0, i+length(from)); done = 1 }
		{ print }
		END { exit !done }' "$root/$src" >"$work/tree/$src"; then
		echo "FAIL $name: mutation did not apply — the source changed, update this script"
		fail=1
		return
	fi
	mutation_applied "$name" && return
	if (cd "$work/tree" && go test -timeout 120s -count=1 ./$pkg/ >"$work/out" 2>&1); then
		echo "FAIL $name: tests stayed green with the property switched off"
		fail=1
	elif mutation_infrastructure_failed "$work/out"; then
		exit 1
	elif ! grep -q -- '--- FAIL' "$work/out"; then
		echo "FAIL $name: mutant did not reach a failing test (build error?)"
		fail=1
	else
		echo "ok   $name: tests went red ($(grep -c -- '--- FAIL' "$work/out") failing)"
	fi
}

# replies are closed objects: an unknown field is refused whole
mutate reply-open-shape    tools.go 'd.DisallowUnknownFields()' '_ = d' 2
# arguments are closed: a value-shaped extra is refused before any request
mutate args-open-shape     tools.go 'd.DisallowUnknownFields()' '_ = d' 1
mutate tool-takes-a-value  tools.go '`json:"wait_seconds"`' '`json:"wait_seconds"`; Value string `json:"value"`'
mutate target-takes-value  tools.go '`json:"consumer"`' '`json:"consumer"`; Value string `json:"value"`'
mutate schema-offers-value tools.go '"secret": str("secret name"), "runner_id": str("runner id"),' '"secret": str("secret name"), "value": str("v"), "runner_id": str("runner id"),'
mutate answer-type-opens   types.go '`json:"owner,omitempty"`' '`json:"owner,omitempty"`; Value string `json:"value"`'
# the token goes to the configured host only, and into no answer
mutate redirect-followed   backend.go 'return http.ErrUseLastResponse' 'return nil'
mutate token-in-error      backend.go '&transportError{"server unreachable"}' '&transportError{"server unreachable " + b.token}'
mutate error-body-echoed   backend.go '&transportError{"server answered with an unreadable error"}' '&transportError{string(raw)}'
mutate token-not-sent      backend.go 'req.Header.Set("Authorization", "Bearer "+b.token)' '_ = b.token'
mutate plain-http-remote   backend.go 'if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {' 'if false {'
mutate isloopback-suffix   backend.go 'if host == "localhost" {' 'if strings.HasSuffix(host, "localhost") {'
mutate isloopback-prefix   backend.go 'if host == "localhost" {' 'if strings.HasPrefix(host, "localhost") {'
mutate input-status-open   tools.go 'if status != http.StatusCreated ||' 'if status == 0 ||'
# the error row keeps its closed shape
mutate class-forwarded     tools.go 'if string(k) == c {' 'if string(k) == c || true {'
mutate message-forwarded   tools.go '"the server refused the request: " + class' 'ae.Message'
mutate request-id-forwarded tools.go 'if !reqid.Valid(rid) {' 'if false {'
mutate deploy-class-open   tools.go 'knownClass(r.ErrorClass) != r.ErrorClass' 'false'
mutate fingerprint-open    tools.go '!fingerprintShape.MatchString(r.Fingerprint)' 'false' 2
mutate deploy-id-unchecked tools.go '!reqid.Valid(r.RequestID)' 'r.RequestID == ""' 2
mutate userinfo-accepted   backend.go 'u.Host == "" || u.User != nil' 'u.Host == ""'
# arguments are validated before they become a path or a query
mutate scope-unchecked     tools.go '!scopeLevel[a.ScopeLevel] || !validUUID(a.ScopeID)' 'false'
mutate secret-id-unchecked tools.go 'if !validUUID(a.SecretID) {' 'if false {'
mutate wait-unbounded      tools.go 'wait < 0 || wait > maxWait' 'wait < 0'
mutate ttl-unbounded       tools.go 'd <= 0 || d > 24*time.Hour' 'd <= 0'
# provider_ref is a locator; an error reply is the closed row
mutate list-secret-unchecked tools.go 'if !closedSecret(s) {' 'if !closedSecret(s) && false {'
mutate meta-secret-unchecked tools.go 'err != nil || !closedSecret(out.Secret) {' 'err != nil {'
mutate ref-scheme-open tools.go 'return provider.ValidRef(s.ProviderRef) && asciiGraphic' 'return (provider.ValidRef(s.ProviderRef) || true) && asciiGraphic'
mutate error-reply-open     backend.go 'if decodeStrict(raw, &ae) != nil {' 'if json.Unmarshal(raw, &ae) != nil {'
mutate error-status-in-body backend.go 'Status     int    `json:"-"`' 'Status     int'
mutate version-fp-unchecked tools.go '&& fingerprintShape.MatchString(v.Fingerprint) &&' '&&'
mutate version-status-open  tools.go '&& versionStatus[v.Status] &&' '&&'
mutate version-unchecked-meta tools.go 'if !closedVersion(v) {' 'if false && !closedVersion(v) {'
mutate secret-name-unchecked tools.go 'plain(s.Name, 253) &&' ''
mutate ref-ascii-open       tools.go 'asciiGraphic(s.ProviderRef, 1024) &&' 'plain(s.ProviderRef, 1024) &&'
mutate ref-length-open      tools.go 'if s == "" || len(s) > max {' 'if s == "" {'
mutate description-unbounded tools.go ' && utf8.RuneCountInString(s.Description) <= 4096' ''
# register_carrier takes metadata only, validates it, and answers a closed row
mutate carrier-takes-a-value  tools.go '`json:"target_field"`' '`json:"target_field"`; Value string `json:"value"`'
mutate carrier-schema-value   tools.go '"consumer": str("service that reads it: launchd:<label> or systemd:<unit>")})},' '"consumer": str("service that reads it: launchd:<label> or systemd:<unit>"), "value": str("v")})},'
mutate carrier-id-unchecked   tools.go 'if !validUUID(a.SecretID) || !plain(a.Version, 64)' 'if !plain(a.Version, 64)'
mutate carrier-host-unchecked tools.go '!plain(a.Host, 253) ||' ''
mutate carrier-status-open    tools.go 'if status != http.StatusCreated || decodeStrict(body, &out) != nil || out.ID == ""' 'if status == 0 || decodeStrict(body, &out) != nil || out.ID == ""'
mutate carrier-foreign-row    tools.go 'out.SecretID != a.SecretID ||' ''
mutate carrier-type-opens     types.go '`json:"fingerprint_match"`' '`json:"fingerprint_match"`; Fingerprint string `json:"fingerprint"`'
mutate carrier-runner-id-dropped types.go '`json:"runner_id,omitempty"`' '`json:"-"`'
mutate carrier-runner-id-unchecked tools.go '(out.RunnerID != "" && !canonicalUUID(out.RunnerID))' 'false'
mutate carrier-runner-id-loose-uuid tools.go 'u != uuid.Nil && u.String() == s' 'u == u'
mutate carrier-version-unchecked tools.go '!plain(a.Version, 64) ||' ''
mutate carrier-kind-unchecked tools.go '!plain(a.TargetKind, 32) ||' ''
mutate carrier-path-unchecked tools.go '!plain(a.TargetPath, 4096) ||' ''
mutate carrier-field-unchecked tools.go '!optional(a.TargetField, 256) ||' ''
mutate carrier-consumer-unchecked tools.go '|| !optional(a.Consumer, 256) {' '{'
mutate carrier-empty-id-accepted tools.go 'out.ID == "" ||' ''
mutate carrier-empty-status-accepted tools.go '|| out.Status == "" ||' '||'
mutate carrier-host-rewritten tools.go '"version": a.Version, "host": a.Host,' '"version": a.Version, "host": strings.ToLower(a.Host) + ".",'
mutate carrier-required-loosened tools.go 'schema([]string{"secret_id", "version", "host", "target_kind", "target_path"}' 'schema([]string{"secret_id", "version", "target_kind", "target_path"}'
# rotate: the agent passes a mode, never a value; the answer is the closed row
mutate rotate-takes-a-value     tools.go '`json:"wait_seconds"`' '`json:"wait_seconds"`; Value string `json:"value"`' 2
mutate rotate-schema-offers-value tools.go '"secret_id":    str("secret id"),' '"secret_id":    str("secret id"), "value": str("v"),'
mutate rotate-mode-open         tools.go '(a.Mode != "generate" && a.Mode != "human_input")' 'false'
mutate rotate-secret-unchecked  tools.go '!validUUID(a.SecretID) || (a.Mode' 'false || (a.Mode'
mutate rotate-wait-unbounded    tools.go 'wait < 0 || wait > maxWait' 'wait < 0' 2
mutate rotate-class-open        tools.go '(r.ErrorClass != "" && !rotateClasses[r.ErrorClass])' 'false'
mutate rotate-fingerprint-open  tools.go '!fingerprintShape.MatchString(r.Fingerprint)' 'false' 1
mutate rotate-version-open      tools.go '(r.Version != "" && !versionRe.MatchString(r.Version))' 'false'
mutate rotate-request-id-open   tools.go '!validUUID(r.RequestID) || len(r.Carriers) > 256' 'false'
mutate rotate-carriers-unbounded tools.go ' || len(r.Carriers) > 256' ''
mutate rotate-carrier-id-open   tools.go '!validUUID(c.CarrierID) || !rotatePhase' 'false || !rotatePhase'
mutate rotate-phase-open        tools.go '!rotatePhase[c.Phase]' 'false'
mutate rotate-state-open        tools.go '!rotateState[c.State]' 'false'
mutate rotate-reply-open-shape  tools.go 'decodeStrict(body, &r) != nil || !validUUID(r.RequestID)' 'json.Unmarshal(body, &r) != nil || !validUUID(r.RequestID)'
mutate rotate-version-before-ok  tools.go '(!r.OK && (r.Version != "" || r.Fingerprint != ""))' 'false'
mutate rotate-class-on-ok        tools.go '(r.OK && r.ErrorClass != "")' 'false'
mutate rotate-accepted-may-be-ok tools.go '(status == http.StatusAccepted && (r.OK || r.ErrorClass != ""))' 'false'
mutate rotate-accepted-may-fail tools.go '(r.OK || r.ErrorClass != "")) ||' '(r.OK)) ||'
mutate rotate-ok-needs-version  tools.go '(r.Version == "" || r.Fingerprint == "")' 'r.Fingerprint == ""'
mutate rotate-ok-needs-fingerprint tools.go '(r.Version == "" || r.Fingerprint == "")' 'r.Version == ""'
mutate rotate-input-status-open tools.go 'if status != http.StatusAccepted || decodeStrict(body, &out)' 'if status == 0 || decodeStrict(body, &out)'
mutate rotate-start-status-open tools.go 'if status != http.StatusAccepted {' 'if false {'
mutate rotate-poll-status-open tools.go 'if status != http.StatusOK && status != http.StatusAccepted {' 'if false {'
mutate rotate-answer-type-opens types.go '`json:"carriers,omitempty"`' '`json:"carriers,omitempty"`; Value string `json:"value"`'
mutate rotate-carrier-type-opens types.go '`json:"state"`' '`json:"state"`; Value string `json:"value"`'
# verify_carriers: a closed, bounded thin wrapper
mutate verify-decode-trailing-open tools.go 'if _, err := d.Token(); !errors.Is(err, io.EOF) {' 'if d.More() {'
mutate verify-carrier-status-open  tools.go '!carrierStatus[c.Status] ||' 'false ||'
mutate verify-carrier-class-open   tools.go '!runnerproto.ErrorClass(c.ErrorClass).Valid())' '!runnerproto.ErrorClass(c.ErrorClass).Valid() && false)'
mutate verify-carrier-fp-open      tools.go '!fingerprintShape.MatchString(r.Fingerprint)' 'false' 1
mutate verify-carrier-request-id-open tools.go '!reqid.Valid(r.RequestID)' 'r.RequestID == ""' 1
mutate verify-carrier-version-open tools.go '|| !optional(r.Version, 128) {' '|| false {' 1
mutate verify-carrier-host-open    tools.go '!plain(c.Host, 253) ||' 'false ||'
mutate verify-carrier-path-open    tools.go '!plain(c.Target.Path, 4096) ||' 'false ||'
mutate verify-carrier-kind-open    tools.go '!plain(c.Target.Kind, 32) ||' 'false ||'
mutate verify-carrier-runner-id-open tools.go '(c.RunnerID != "" && !validUUID(c.RunnerID)) ||' 'false ||'
mutate verify-carrier-row-id-open  tools.go '!validUUID(c.ID) ||' 'false ||'
mutate verify-carrier-rows-unbounded tools.go ' || len(r.Carriers) > maxCarrierRows' ''
mutate verify-wait-unbounded tools.go '|| wait < 0 || wait > maxWait {' '{' 2
mutate verify-takes-a-value tools.go '`json:"wait_seconds"`' '`json:"wait_seconds"`; Value string `json:"value"`' 2
mutate verify-carrier-row-opens    types.go '`json:"error_class,omitempty"`' '`json:"error_class,omitempty"`; Value string `json:"value"`' 2
# protocol
mutate id-any-echoed       server.go '!notification && !integerID.Match(req.ID) {' '!notification && false {'
mutate id-string-allowed   server.go '{0,15})$`)' '{0,15})$|^".*"$`)'
mutate id-digits-unbounded server.go '[1-9][0-9]{0,15}' '[1-9][0-9]*'
mutate id-negative-zero    server.go '`^(0|-?[1-9]' '`^(-?0|-?[1-9]'
mutate method-echoed       server.go 'return fail(codeMethodNotFound, "method not found")' 'return fail(codeMethodNotFound, "method not found: "+req.Method)'
mutate parse-line-echoed   server.go 'Error: &rpcError{codeParse, "parse error"}}' 'Error: &rpcError{codeParse, "parse error " + string(line)}}'
mutate notification-answered server.go 'notification := len(req.ID) == 0' 'notification := false'
mutate call-without-id-run server.go 'return nil // a call nobody can read the answer of is not run' '_ = notification'

if mutation_apply_only; then
	:
elif (cd "$root" && go test -timeout 120s -count=1 ./$pkg/ >/dev/null 2>&1); then
	echo "ok   baseline: tests green on the real code"
else
	echo "FAIL baseline: tests are red on the real code"
	fail=1
fi

exit $fail
