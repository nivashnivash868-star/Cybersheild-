-- Read-only window onto CyberShield's own data for Zetaris. Run as the database owner (see register_in_zetaris.sh).
-- Exposes the SOC working data only. Deliberately NOT exposed: users, sessions, password-reset and feed tokens, MFA material,
-- settings, secret findings, employee records and reputation-cache rows.
CREATE SCHEMA IF NOT EXISTS zetaris_export;

CREATE OR REPLACE VIEW zetaris_export.security_events    AS SELECT * FROM public.security_events;
CREATE OR REPLACE VIEW zetaris_export.incidents          AS SELECT * FROM public.incidents;
CREATE OR REPLACE VIEW zetaris_export.decision_requests  AS SELECT * FROM public.decision_requests;
CREATE OR REPLACE VIEW zetaris_export.agent_runs         AS SELECT * FROM public.agent_runs;
CREATE OR REPLACE VIEW zetaris_export.response_actions   AS SELECT * FROM public.response_actions;
CREATE OR REPLACE VIEW zetaris_export.response_jobs      AS SELECT * FROM public.response_jobs;
CREATE OR REPLACE VIEW zetaris_export.blocklist_entries  AS SELECT * FROM public.blocklist_entries;
CREATE OR REPLACE VIEW zetaris_export.threat_analyses    AS SELECT * FROM public.threat_analyses;
CREATE OR REPLACE VIEW zetaris_export.audit_logs         AS SELECT * FROM public.audit_logs;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zetaris_ro') THEN
    CREATE ROLE zetaris_ro LOGIN;
  END IF;
END $$;
-- password is set separately: ALTER ROLE zetaris_ro PASSWORD '...'
REVOKE ALL ON SCHEMA public FROM zetaris_ro;
GRANT USAGE ON SCHEMA zetaris_export TO zetaris_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA zetaris_export TO zetaris_ro;
ALTER ROLE zetaris_ro SET default_transaction_read_only = on;
