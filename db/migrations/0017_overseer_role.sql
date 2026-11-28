-- Existing installations retain the original role constraint from table creation.
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_role_ck;
ALTER TABLE agents ADD CONSTRAINT agents_role_ck CHECK (role IN ('goals','main','planner','worker','assistant','overseer'));
