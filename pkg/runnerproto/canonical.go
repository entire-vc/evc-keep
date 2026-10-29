package runnerproto

import (
	"bytes"
	"encoding/binary"
	"time"
	"unicode/utf8"
)

// jobDomain opens every encoded job, so a signature over a job can never be
// read as a signature over anything else the server signs.
const jobDomain = "keep/job/v1\x00"

// Field tags of the canonical encoding. Fields appear in ascending tag
// order, each exactly once when present; optional fields are omitted when
// empty and must not appear empty. There is one encoding per job, so the
// runner can verify the signature over the bytes and parse only after.
//
// APPEND-ONLY. These byte values are wire format, not an implementation
// detail: they are baked into every already-signed Job (this file) and into
// value.Info's HPKE info string (value.go), which both address fields by
// these same constants directly rather than by name. A tag inserted between
// two existing ones silently renumbers every tag after it — a job signed, or
// a value sealed, by the previous binary then fails to decode (Job) or opens
// under the wrong info string (Info) on the new one, a closed failure either
// way but the same class of two-phase-rotation incompatibility across a
// version boundary. tagTargetConsumer (right after tagNonce, above) is the
// concrete example: inserting it between tagTargetUnit and tagTargetMode
// once made a job signed by the previous binary fail to decode ("field is
// not UTF-8" — the old Mode field's raw 8-byte binary landed on the new tag
// number for Consumer, which the decoder validates as UTF-8).
//
// When adding a new tag:
//  1. Append it as the new last entry, immediately above tagEnd. Never
//     insert it between existing tags, and never reuse or renumber a
//     retired one.
//  2. If the field's wire encoding is not valid UTF-8 (binary.BigEndian
//     integers, raw nonce/param bytes, anything via e.field/e.u64/e.i64
//     rather than e.str/e.opt) — add the new tag to binaryTag below, and
//     give it its own non-UTF-8 test fixture (see TestNonUTF8NonceRoundTrips
//     in runnerproto_test.go, which covers only tagNonce): a forgotten entry
//     is not reliably caught by chance, only by whichever fixed test value
//     that field happens to use.
//  3. TestInfoHistoricalWireFormat, TestJobHistoricalWireFormat and
//     TestExecJobHistoricalWireFormat (runnerproto_test.go) each pin the
//     historical bytes of Info/encodeJob for a fixed job; they must stay
//     green with no change to their expected literals.
//     TestDecodeJobAcceptsPreConsumerWireFormat and TestConsumerRoundTrip
//     do the same for tagTargetConsumer specifically, pinning it as the
//     last tag encodeJob ever emits.
//     scripts/check-runnerproto-mutations.sh proves a mid-list insertion
//     turns them red.
const (
	tagJobID byte = iota + 1
	tagOrgID
	tagRunnerID
	tagStoreID
	tagProvider
	tagSecretName
	tagSecretScope
	tagExpectedVersion
	tagExpectedFingerprint
	tagAction
	tagTargetKind
	tagTargetPath
	tagTargetField
	tagTargetUnit
	tagTargetMode
	tagTargetUID
	tagTargetGID
	tagExecTemplateID
	tagExecDigest
	tagExecParams
	tagIssuedAt
	tagNotAfter
	tagNonce
	tagTargetConsumer
	tagEnd
)

const maxFieldLen = 64 << 10

type encoder struct{ b bytes.Buffer }

func (e *encoder) field(tag byte, v []byte) {
	e.b.WriteByte(tag)
	e.b.Write(binary.AppendUvarint(nil, uint64(len(v)))) //nolint:gosec // G115: a length is never negative
	e.b.Write(v)
}

func (e *encoder) str(tag byte, s string) { e.field(tag, []byte(s)) }

func (e *encoder) opt(tag byte, s string) {
	if s != "" {
		e.str(tag, s)
	}
}

func (e *encoder) u64(tag byte, v uint64) { e.field(tag, binary.BigEndian.AppendUint64(nil, v)) }

// i64 encodes v as two's complement, big-endian.
func (e *encoder) i64(tag byte, v int64) {
	e.u64(tag, uint64(v)) //nolint:gosec // G115: two's complement is the encoding; decoded back with int64()
}

// EncodeJob returns the canonical bytes of j. It validates j first: an
// invalid job has no encoding.
func EncodeJob(j Job) ([]byte, error) {
	if err := j.Validate(); err != nil {
		return nil, err
	}
	return encodeJob(j), nil
}

func encodeJob(j Job) []byte {
	var e encoder
	e.b.WriteString(jobDomain)
	e.str(tagJobID, j.JobID)
	e.str(tagOrgID, j.OrgID)
	e.str(tagRunnerID, j.RunnerID)
	e.str(tagStoreID, j.Secret.StoreID)
	e.str(tagProvider, j.Secret.Provider)
	e.str(tagSecretName, j.Secret.Name)
	e.str(tagSecretScope, j.Secret.Scope)
	e.str(tagExpectedVersion, j.ExpectedVersion)
	e.str(tagExpectedFingerprint, j.ExpectedFingerprint)
	e.str(tagAction, string(j.Action))
	if j.Exec == nil {
		e.str(tagTargetKind, string(j.Target.Kind))
		e.str(tagTargetPath, j.Target.Path)
		e.opt(tagTargetField, j.Target.Field)
		e.opt(tagTargetUnit, j.Target.Unit)
		e.u64(tagTargetMode, uint64(j.Target.Mode))
		e.i64(tagTargetUID, j.Target.UID)
		e.i64(tagTargetGID, j.Target.GID)
	} else {
		e.str(tagExecTemplateID, j.Exec.TemplateID)
		e.str(tagExecDigest, j.Exec.Digest)
		if len(j.Exec.Params) > 0 {
			var p encoder
			for _, k := range sortedKeys(j.Exec.Params) {
				p.str(1, k)
				p.str(2, j.Exec.Params[k])
			}
			e.field(tagExecParams, p.b.Bytes())
		}
	}
	e.i64(tagIssuedAt, j.IssuedAt.Unix())
	e.i64(tagNotAfter, j.NotAfter.Unix())
	e.field(tagNonce, j.Nonce)
	// Consumer is a Target field logically, but its tag was added after
	// Nonce (see the tag block's doc comment) and canonical order is by
	// tag number, not by field grouping — it is always emitted last, and
	// is empty (so opt skips it) for an Exec job, whose Target is zero.
	e.opt(tagTargetConsumer, j.Target.Consumer)
	return e.b.Bytes()
}

type decoder struct {
	b    []byte
	last byte
}

func (d *decoder) next() (byte, []byte, error) {
	if len(d.b) == 0 {
		return tagEnd, nil, nil
	}
	tag := d.b[0]
	if tag <= d.last || tag >= tagEnd {
		return 0, nil, invalid("field out of order or unknown")
	}
	v, rest, err := readField(d.b[1:], maxFieldLen)
	if err != nil {
		return 0, nil, err
	}
	d.b = rest
	d.last = tag
	return tag, v, nil
}

// DecodeJob parses canonical bytes. It accepts exactly the bytes EncodeJob
// would produce for the decoded job and nothing else. Call it only on bytes
// whose signature has been verified (VerifyJob does both).
func DecodeJob(b []byte) (Job, error) {
	if !bytes.HasPrefix(b, []byte(jobDomain)) {
		return Job{}, invalid("wrong domain")
	}
	d := decoder{b: b[len(jobDomain):]}
	var (
		j        Job
		isExec   bool
		mode     uint64
		uid, gid int64
	)
	for {
		tag, v, err := d.next()
		if err != nil {
			return Job{}, err
		}
		if tag == tagEnd {
			break
		}
		if !binaryTag(tag) && !utf8.Valid(v) {
			return Job{}, invalid("field is not UTF-8")
		}
		s := string(v)
		switch tag {
		case tagJobID:
			j.JobID = s
		case tagOrgID:
			j.OrgID = s
		case tagRunnerID:
			j.RunnerID = s
		case tagStoreID:
			j.Secret.StoreID = s
		case tagProvider:
			j.Secret.Provider = s
		case tagSecretName:
			j.Secret.Name = s
		case tagSecretScope:
			j.Secret.Scope = s
		case tagExpectedVersion:
			j.ExpectedVersion = s
		case tagExpectedFingerprint:
			j.ExpectedFingerprint = s
		case tagAction:
			j.Action = Action(s)
		case tagTargetKind:
			j.Target.Kind = TargetKind(s)
		case tagTargetPath:
			j.Target.Path = s
		case tagTargetField:
			j.Target.Field = s
		case tagTargetUnit:
			j.Target.Unit = s
		case tagTargetMode, tagTargetUID, tagTargetGID, tagIssuedAt, tagNotAfter:
			if len(v) != 8 {
				return Job{}, invalid("integer field")
			}
			n := binary.BigEndian.Uint64(v)
			sn := int64(n) //nolint:gosec // G115: two's complement, see encoder.i64
			switch tag {
			case tagTargetMode:
				mode = n
			case tagTargetUID:
				uid = sn
			case tagTargetGID:
				gid = sn
			case tagIssuedAt:
				j.IssuedAt = time.Unix(sn, 0).UTC()
			case tagNotAfter:
				j.NotAfter = time.Unix(sn, 0).UTC()
			}
		case tagExecTemplateID, tagExecDigest, tagExecParams:
			if !isExec {
				isExec, j.Exec = true, &Exec{}
			}
			switch tag {
			case tagExecTemplateID:
				j.Exec.TemplateID = s
			case tagExecDigest:
				j.Exec.Digest = s
			default:
				p, err := decodeParams(v)
				if err != nil {
					return Job{}, err
				}
				j.Exec.Params = p
			}
		case tagNonce:
			j.Nonce = append([]byte(nil), v...)
		case tagTargetConsumer:
			j.Target.Consumer = s
		}
	}
	if mode > 0o777 {
		return Job{}, invalid("integer field out of range")
	}
	j.Target.Mode, j.Target.UID, j.Target.GID = uint32(mode), uid, gid
	if err := j.Validate(); err != nil {
		return Job{}, err
	}
	// The one-encoding rule, enforced rather than assumed: an absent
	// required field, an optional field sent empty, a time with sub-second
	// precision all re-encode differently.
	if !bytes.Equal(encodeJob(j), b) {
		return Job{}, invalid("non-canonical encoding")
	}
	return j, nil
}

// readField reads a minimal uvarint length and that many bytes.
func readField(b []byte, limit int) (v, rest []byte, err error) {
	n, k := binary.Uvarint(b)
	if k <= 0 {
		return nil, nil, invalid("truncated field")
	}
	// Uvarint accepts over-long encodings; the canonical one is the shortest.
	if k != len(binary.AppendUvarint(nil, n)) {
		return nil, nil, invalid("non-minimal length")
	}
	b = b[k:]
	if n > uint64(min(limit, len(b))) { //nolint:gosec // G115: both are non-negative
		return nil, nil, invalid("truncated field")
	}
	return b[:n], b[n:], nil
}

// binaryTag reports whether tag's wire encoding is not text — i.e. it was
// written with e.field/e.u64/e.i64 rather than e.str/e.opt. DecodeJob skips
// the UTF-8 check for these; every other tag must decode as valid UTF-8 or
// the job is rejected. CHECKLIST: a new tag whose value is not built from a
// Go string (integers, raw bytes, a nested sub-encoding such as exec
// params) belongs in this switch. Forgetting it is not reliably caught by
// chance: a binary value that happens to also be valid UTF-8 (small
// integers, short ASCII-range byte strings) decodes without complaint
// either way — see TestNonUTF8NonceRoundTrips, which pins a nonce that is
// guaranteed not to be, specifically so a missing entry has something to
// catch it.
func binaryTag(tag byte) bool {
	switch tag {
	case tagNonce, tagExecParams, tagTargetMode, tagTargetUID, tagTargetGID, tagIssuedAt, tagNotAfter:
		return true
	}
	return false
}

func decodeParams(b []byte) (map[string]string, error) {
	m := map[string]string{}
	for len(b) > 0 {
		var kv [2]string
		for i, want := range []byte{1, 2} {
			if len(b) == 0 || b[0] != want {
				return nil, invalid("exec params")
			}
			v, rest, err := readField(b[1:], maxFieldLen)
			if err != nil || !utf8.Valid(v) {
				return nil, invalid("exec params")
			}
			kv[i], b = string(v), rest
		}
		if _, dup := m[kv[0]]; dup {
			return nil, invalid("exec params")
		}
		m[kv[0]] = kv[1]
	}
	if len(m) == 0 {
		return nil, invalid("exec params present but empty")
	}
	return m, nil
}
