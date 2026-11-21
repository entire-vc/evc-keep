#!/bin/sh
# Entry point of the stand's keep-server container: the settings the stand's
# init step wrote (database URL, key and certificate paths) are read from the
# volume, so that no value sits in the compose file or the image.
set -eu
. /stand/server.env
exec /usr/local/bin/keep-server "$@"
