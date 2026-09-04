-- Ruolo applicativo Defenix.
-- Deliberatamente NON superuser e senza BYPASSRLS: le policy di Row Level
-- Security definite dalla migrazione 0001 devono valere anche per lui.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'defenix_app') THEN
        CREATE ROLE defenix_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
    END IF;
END
$$;

-- L'audit log e' append-only: si revocano UPDATE e DELETE a livello di
-- privilegi, oltre ai trigger applicati dalla migrazione.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO defenix_app;
