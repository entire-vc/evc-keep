package builtin

import (
	"context"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// meshMetadataSQL is the whole of the metadata probe's storage access: two
// scalars of the newest active version, never a ciphertext, a wrapped key or
// a key id. A test pins this text, and the reader is a single QueryRow.
const meshMetadataSQL = `SELECT version::text, octet_length(ciphertext) - 28 AS length
FROM keep_envelope
WHERE store_org = $1 AND store_workspace = '' AND store_project = '' AND store_user = ''
  AND secret_id = $2 AND status = 'active'
ORDER BY version DESC LIMIT 1`

// meshMetadataMaxLength is the longest value a workspace may store.
const meshMetadataMaxLength = 32 << 10

// MetadataSecret answers the version and the length of the newest active
// version of ref in workspace's namespace without opening it: no Resolve, no
// decrypt, no fingerprint, no write. The length is the stored size less the
// fixed AES-GCM nonce and tag (gcmNonceAndTag); a size outside what Keep can
// have written is a storage fault, not a clamped answer. A ref the workspace
// never wrote, or whose versions are all disabled or erased, is
// ErrMeshSecretNotFound, a malformed one ErrMeshSecretInvalid. Fingerprint is
// left empty on purpose.
func (m *MeshVault) MetadataSecret(ctx context.Context, org, workspace, ref string) (MeshSecretMeta, error) {
	path, err := meshSecretPath(workspace, ref)
	if err != nil {
		return MeshSecretMeta{}, err
	}
	var version string
	var length int
	err = m.local.pool.QueryRow(ctx, meshMetadataSQL, org, path).Scan(&version, &length)
	if errors.Is(err, pgx.ErrNoRows) {
		return MeshSecretMeta{}, ErrMeshSecretNotFound
	}
	if err != nil || length < 1 || length > meshMetadataMaxLength || !meshVersionValid(version) {
		return MeshSecretMeta{}, errMeshVault
	}
	return MeshSecretMeta{Version: version, Length: length}, nil
}

// meshVersionValid is a canonical positive decimal that fits an int64.
func meshVersionValid(v string) bool {
	n, err := strconv.ParseInt(v, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == v
}
