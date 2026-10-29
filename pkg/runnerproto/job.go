package runnerproto

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
)

// Action is what a job asks the runner to do.
type Action string

const (
	// ActionDeploy writes the secret into the target.
	ActionDeploy Action = "deploy"
	// ActionExec runs an approved exec_with_secret template.
	ActionExec Action = "exec"
	// ActionVerify compares the target's fingerprint with the expected one.
	ActionVerify Action = "verify"
)

// TargetKind is a closed list of places a runner can write to. There is no
// network kind and there must never be one (R-POL-3): a value leaves the host
// only through a provider, never through a target.
type TargetKind string

const (
	TargetEnvFile           TargetKind = "env-file"
	TargetFile              TargetKind = "file"
	TargetLaunchdEnv        TargetKind = "launchd-env"
	TargetSystemdCredential TargetKind = "systemd-credential" //nolint:gosec // G101: a target kind name, not a credential
	TargetMCPConfig         TargetKind = "mcp-config"
	TargetHermesConfig      TargetKind = "hermes-config"
)

// TargetKinds lists every known kind.
var TargetKinds = []TargetKind{
	TargetEnvFile, TargetFile, TargetLaunchdEnv,
	TargetSystemdCredential, TargetMCPConfig, TargetHermesConfig,
}

func knownKind(k TargetKind) bool {
	for _, x := range TargetKinds {
		if x == k {
			return true
		}
	}
	return false
}

// ProviderBuiltin is the provider whose value the server delivers to the
// runner with ValueRequest. Every other provider is resolved by the runner.
const ProviderBuiltin = "builtin"

// MaxJobTTL bounds NotAfter-IssuedAt. It also bounds how long the replay
// journal must remember a job id.
const MaxJobTTL = 15 * time.Minute

// ClockSkew is the tolerance for the runner's clock against the server's.
const ClockSkew = 30 * time.Second

// NonceSize is the length of Job.Nonce.
const NonceSize = 16

// SecretRef names a secret. It never carries a value.
type SecretRef struct {
	StoreID  string
	Provider string
	Name     string
	Scope    string
}

// Target is where the value goes. Path is syntax-checked here and opened
// with openat+O_NOFOLLOW by the target writer.
type Target struct {
	Kind TargetKind
	Path string
	// Field is the variable or key inside the file: an env name for
	// env-file, launchd-env and hermes-config (a line in the profile's .env),
	// a dotted key for mcp-config. Empty for file and systemd-credential.
	Field string
	// Unit is the launchd label or systemd unit that consumes the target.
	Unit string
	// Consumer is the service restarted and health-checked after a
	// successful deploy: "launchd:<label>" or "systemd:<unit>". Empty means
	// no restart. Deliberately its own field, not a reuse of Unit: Unit is
	// already consumed verbatim (unprefixed) by the systemd-credential
	// target as the credential name, and reformatting it would change that
	// shipped behavior.
	Consumer string
	// Mode, UID and GID are the permissions and owner of the written file:
	// the consumer's, never the agents' (host policy).
	Mode uint32
	UID  int64
	GID  int64
}

// Exec names an approved exec_with_secret template. The runner holds its
// own copy of the template and checks Digest against it.
type Exec struct {
	TemplateID string
	// Digest is lowercase hex SHA-256 of the approved template.
	Digest string
	Params map[string]string
}

// Job is one unit of work for one runner. Every field is covered by the
// server's signature.
type Job struct {
	JobID               string
	OrgID               string
	RunnerID            string
	Secret              SecretRef
	ExpectedVersion     string
	ExpectedFingerprint string
	Action              Action
	// Target is set for deploy and verify, zero for exec.
	Target Target
	// Exec is set for exec only.
	Exec     *Exec
	IssuedAt time.Time
	NotAfter time.Time
	Nonce    []byte
}

// ErrInvalidJob wraps every structural problem with a job.
var ErrInvalidJob = errors.New("runnerproto: invalid job")

var (
	uuidV7Re   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	idRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	nameRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./-]{0,127}$`)
	scopeRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	versionRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	envFieldRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	keyFieldRe = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){0,15}$`)
	unitRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$`)
	consumerRe = regexp.MustCompile(`^(launchd|systemd):[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$`)
	digestRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	paramRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidJob, fmt.Sprintf(format, a...))
}

// Validate checks the job's structure. It does not check the signature,
// the clock, the runner identity or the host policy.
func (j Job) Validate() error {
	switch {
	case !uuidV7Re.MatchString(j.JobID):
		return invalid("job_id is not a UUIDv7")
	case !idRe.MatchString(j.OrgID):
		return invalid("org_id")
	case !idRe.MatchString(j.RunnerID):
		return invalid("runner_id")
	case !idRe.MatchString(j.Secret.StoreID):
		return invalid("store_id")
	case !idRe.MatchString(j.Secret.Provider):
		return invalid("provider")
	case !nameRe.MatchString(j.Secret.Name):
		return invalid("secret name")
	case !scopeRe.MatchString(j.Secret.Scope):
		return invalid("secret scope")
	case !versionRe.MatchString(j.ExpectedVersion):
		return invalid("expected_version")
	case !fingerprint.Valid(j.ExpectedFingerprint):
		return invalid("expected_fingerprint")
	case len(j.Nonce) != NonceSize:
		return invalid("nonce must be %d bytes", NonceSize)
	case j.IssuedAt.IsZero() || j.NotAfter.IsZero():
		return invalid("issued_at and not_after are required")
	case !j.NotAfter.After(j.IssuedAt):
		return invalid("not_after must be after issued_at")
	case j.NotAfter.Sub(j.IssuedAt) > MaxJobTTL:
		return invalid("job lifetime exceeds %s", MaxJobTTL)
	}
	switch j.Action {
	case ActionDeploy, ActionVerify:
		if j.Exec != nil {
			return invalid("exec is set on a %s job", j.Action)
		}
		if j.Action == ActionVerify && j.Target.Consumer != "" {
			// Check's consumer-allowlist gate sits after its ActionVerify
			// early return (nothing to authorize: verify never restarts
			// anything), so a verify job naming a consumer would otherwise
			// carry it past Check unchecked. Refusing it here, at job
			// structure validation, closes that off before Check ever
			// runs — a verify job has no business naming a consumer at all.
			return invalid("consumer is not used by a verify job")
		}
		return j.Target.Validate()
	case ActionExec:
		if j.Target != (Target{}) {
			return invalid("target is set on an exec job")
		}
		if j.Exec == nil {
			return invalid("exec job without a template")
		}
		return j.Exec.validate()
	default:
		return invalid("unknown action")
	}
}

// Validate checks the target's own fields: kind, absolute clean path, the
// field's shape for its kind, the unit label, mode and owner. It is what
// Job.Validate applies to a job's target, exported so a writer that receives
// a Target from somewhere else (internal/targets) can refuse a malformed one
// before it touches the filesystem, instead of trusting that every caller
// already validated the job.
func (t Target) Validate() error {
	if !knownKind(t.Kind) {
		return invalid("unknown target kind")
	}
	if err := ValidatePath(t.Path); err != nil {
		return err
	}
	if err := t.validateField(); err != nil {
		return err
	}
	if t.Unit != "" && !unitRe.MatchString(t.Unit) {
		return invalid("unit")
	}
	switch {
	case t.Mode == 0 || t.Mode&^0o777 != 0:
		return invalid("mode must be non-zero permission bits only")
	case t.UID < 0 || t.UID > 1<<31-1 || t.GID < 0 || t.GID > 1<<31-1:
		return invalid("uid and gid must be set")
	}
	return nil
}

// kindHasField reports whether a target of kind k names a variable or key
// inside the file.
func kindHasField(k TargetKind) bool {
	switch k {
	case TargetEnvFile, TargetLaunchdEnv, TargetMCPConfig, TargetHermesConfig:
		return true
	}
	return false
}

func (t Target) validateField() error {
	switch t.Kind {
	case TargetEnvFile, TargetLaunchdEnv, TargetHermesConfig:
		if !envFieldRe.MatchString(t.Field) {
			return invalid("field must be an environment variable name")
		}
	case TargetMCPConfig:
		if !keyFieldRe.MatchString(t.Field) {
			return invalid("field must be a dotted key")
		}
	default:
		if t.Field != "" {
			return invalid("field is not used by %s", t.Kind)
		}
	}
	if t.Consumer != "" && !consumerRe.MatchString(t.Consumer) {
		return invalid("consumer")
	}
	return nil
}

func (e *Exec) validate() error {
	switch {
	case !idRe.MatchString(e.TemplateID):
		return invalid("template_id")
	case !digestRe.MatchString(e.Digest):
		return invalid("template digest")
	}
	for _, k := range sortedKeys(e.Params) {
		if !paramRe.MatchString(k) || len(e.Params[k]) > 1024 {
			return invalid("exec param")
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// NeedsValue reports whether the runner must obtain the value to do the job.
func (j Job) NeedsValue() bool { return j.Action == ActionDeploy || j.Action == ActionExec }

// NeedsFingerprintKey reports whether the runner is given the store's
// fingerprint key, and no value, to do the job: only a verify job. The key
// lets the runner compute the fingerprint of what a carrier holds; nothing
// else about the secret reaches the host.
func (j Job) NeedsFingerprintKey() bool { return j.Action == ActionVerify }
