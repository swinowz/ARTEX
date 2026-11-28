ALTER TABLE agents ADD COLUMN IF NOT EXISTS overseer_cadence_mode TEXT NOT NULL DEFAULT 'seconds' CHECK (overseer_cadence_mode IN ('seconds','rounds'));
ALTER TABLE agents ADD COLUMN IF NOT EXISTS overseer_interval_seconds INTEGER NOT NULL DEFAULT 90 CHECK (overseer_interval_seconds > 0);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS overseer_interval_rounds INTEGER NOT NULL DEFAULT 5 CHECK (overseer_interval_rounds > 0);
