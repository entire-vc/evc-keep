FROM postgres:17-bookworm
# Explicit modes: a checkout made under umask 077 must still build a working stand.
COPY --chmod=0644 init.sql /docker-entrypoint-initdb.d/10-keep.sql
