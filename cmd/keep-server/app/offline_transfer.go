package app

// keep-server offline-transfer: the operator commands of the offline scoped
// transfer. The dispatch runs before runServe and starts no listener, worker
// or rotation. Arguments carry only operation names, public identities and
// absolute carrier paths; keys, DSNs and plaintext never travel as arguments
// or output. Every command ends with an exit code and a closed receipt of
// key=value metadata; a refusal is a static, allowlisted line.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/transfercarrier"
)

const offlineTransferUsage = "usage: keep-server offline-transfer recipient|export|finalize|import (see the runbook for the flags)"

func runOfflineTransfer(ctx context.Context, args []string) int {
	return offlineTransfer(ctx, args, os.Stdout, os.Stderr)
}

func offlineTransfer(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, offlineTransferUsage)
		return 2
	}
	switch args[0] {
	case "recipient":
		return transferRecipient(args[1:], stdout, stderr)
	case "export":
		return transferExport(ctx, args[1:], stdout, stderr)
	case "finalize":
		return transferFinalize(ctx, args[1:], stdout, stderr)
	case "import":
		return transferImport(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintln(stderr, offlineTransferUsage)
		return 2
	}
}

func transferFail(stderr io.Writer, op, reason string) int {
	_, _ = fmt.Fprintf(stderr, "offline-transfer %s failed: reason=%s\n", op, reason)
	return 1
}

// transferRecipient creates the target's recipient keypair. The private key
// goes to a new 0600 carrier and nowhere else; the public key goes to a
// second carrier for the source operator. The receipt names only the public
// fingerprint, which the source operator pins independently.
func transferRecipient(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("offline-transfer recipient", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	privPath := fs.String("private-file", "", "")
	pubPath := fs.String("public-file", "", "")
	if err := fs.Parse(args); err != nil || *privPath == "" || *pubPath == "" || fs.NArg() != 0 || *privPath == *pubPath {
		_, _ = fmt.Fprintln(stderr, offlineTransferUsage)
		return 2
	}
	pub, priv, err := builtin.NewTransferRecipient()
	if err != nil {
		return transferFail(stderr, "recipient", "key_generation")
	}
	defer clear(priv)
	if err := transfercarrier.Create(*privPath, priv); err != nil {
		return transferFail(stderr, "recipient", carrierReason(err))
	}
	if err := transfercarrier.Create(*pubPath, pub); err != nil {
		// The private carrier is ours and unused: remove it rather than
		// leave a key with no public half.
		_ = os.Remove(*privPath)
		return transferFail(stderr, "recipient", carrierReason(err))
	}
	sum := sha256.Sum256(pub)
	_, _ = fmt.Fprintf(stdout, "offline-transfer recipient: outcome=created recipient_fingerprint=%s\n", hex.EncodeToString(sum[:]))
	return 0
}

func carrierReason(err error) string {
	if ce, ok := err.(transfercarrier.Error); ok {
		return "carrier_" + ce.Reason
	}
	return "carrier"
}
