-- The server's database: a non-superuser role that migrates and serves
-- (migration 00005 needs CREATEROLE), and the log settings keep-server
-- refuses to start without (it would otherwise leak statements into the log).
CREATE ROLE keep LOGIN CREATEROLE;
CREATE DATABASE keep OWNER keep;
ALTER DATABASE keep SET log_error_verbosity = 'terse';
ALTER DATABASE keep SET log_min_error_statement = 'panic';
ALTER DATABASE keep SET log_statement = 'none';
ALTER DATABASE keep SET log_min_duration_statement = -1;
ALTER DATABASE keep SET log_min_duration_sample = -1;
ALTER DATABASE keep SET log_transaction_sample_rate = 0;
ALTER DATABASE keep SET log_min_messages = 'fatal';
