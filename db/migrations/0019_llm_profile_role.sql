ALTER TABLE llm_profiles
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'worker'
    CHECK (role IN ('worker','overseer','both'));

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'llm_profiles_default_role_ck') THEN
        ALTER TABLE llm_profiles ADD CONSTRAINT llm_profiles_default_role_ck
            CHECK (NOT is_default OR role IN ('worker','both'));
    END IF;
END $$;
