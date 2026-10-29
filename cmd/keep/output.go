package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

func newTabwriter(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
}

// writeJSONValue is the single --json rendering path for every command: it
// only ever receives the local wire structs from commands.go, which carry
// no field beyond what internal/api's JSON already exposes — there is no
// separate "public" struct to keep in sync, so a field can't leak here
// without also being visible to a plain HTTP client.
func writeJSONValue(w io.Writer, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(escapeJSONControls(buf.Bytes()))
	return err
}

// encoding/json already escapes C0 and line separators in strings. Keep
// ASCII whitespace outside strings intact, and escape the remaining Cc/Cf
// characters. Supplementary format runes need a JSON surrogate pair.
func escapeJSONControls(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	for _, r := range string(raw) {
		if r >= 0x7f && unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				out = fmt.Appendf(out, "\\u%04x\\u%04x", hi, lo)
			} else {
				out = fmt.Appendf(out, "\\u%04x", r)
			}
		} else {
			out = utf8.AppendRune(out, r)
		}
	}
	return out
}

// cell makes a server-supplied field safe to print on a terminal: the
// server stores these strings as given, so a hostile one must not reach the
// screen as an escape sequence.
func cell(s string) string { return sanitizeText(s, maxErrTextRunes) }

// A *tabwriter.Writer only buffers on each Fprint* call — the real write to
// w happens inside Flush, whose error this function already returns, so an
// individual buffering write's own (effectively unreachable) error is
// deliberately ignored rather than threaded through every line.
func writeSecretTable(w io.Writer, secrets []secret) error {
	tw := newTabwriter(w)
	_, _ = fmt.Fprintln(tw, "NAME\tSCOPE\tCLASS\tTYPE\tSTORE\tPROVIDER_REF")
	for _, s := range secrets {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", cell(s.Name), cell(s.Scope), cell(s.Class), cell(s.Type), cell(s.Store.Name), cell(s.ProviderRef))
	}
	return tw.Flush()
}

func writeSecretDetail(w io.Writer, s secret) error {
	tw := newTabwriter(w)
	_, _ = fmt.Fprintf(tw, "name:\t%s\n", cell(s.Name))
	_, _ = fmt.Fprintf(tw, "scope:\t%s\n", cell(s.Scope))
	_, _ = fmt.Fprintf(tw, "class:\t%s\n", cell(s.Class))
	_, _ = fmt.Fprintf(tw, "type:\t%s\n", cell(s.Type))
	if s.Description != "" {
		_, _ = fmt.Fprintf(tw, "description:\t%s\n", cell(s.Description))
	}
	_, _ = fmt.Fprintf(tw, "store:\t%s (%s)\n", cell(s.Store.Name), cell(s.Store.Provider))
	_, _ = fmt.Fprintf(tw, "provider_ref:\t%s\n", cell(s.ProviderRef))
	_, _ = fmt.Fprintf(tw, "created_at:\t%s\n", s.CreatedAt.Format("2006-01-02T15:04:05Z07:00"))
	_, _ = fmt.Fprintf(tw, "updated_at:\t%s\n", s.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"))
	return tw.Flush()
}

func writeVersionTable(w io.Writer, versions []secretVersion) error {
	tw := newTabwriter(w)
	_, _ = fmt.Fprintln(tw, "VERSION\tSTATUS\tFINGERPRINT\tLENGTH\tCREATED_AT")
	for _, v := range versions {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", cell(v.Version), cell(v.Status), cell(v.Fingerprint), v.Length, v.CreatedAt.Format("2006-01-02T15:04:05Z07:00"))
	}
	return tw.Flush()
}

func writeAuditVerifyDetail(w io.Writer, r auditVerifyResult) error {
	tw := newTabwriter(w)
	_, _ = fmt.Fprintf(tw, "ok:\t%t\n", r.OK)
	_, _ = fmt.Fprintf(tw, "checked:\t%d\n", r.Checked)
	if !r.OK {
		_, _ = fmt.Fprintf(tw, "broken_id:\t%s\n", cell(r.BrokenID))
		_, _ = fmt.Fprintf(tw, "broken_position:\t%d\n", r.BrokenPosition)
		_, _ = fmt.Fprintf(tw, "break_kind:\t%s\n", cell(r.BreakKind))
	}
	return tw.Flush()
}
