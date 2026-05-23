-- ============================================================
-- Idempotent migration — safe to run multiple times.
-- ============================================================

-- Security fix: the original 001_initial_schema.sql declared two RLS
-- policies on `messages`:
--
--   1. "Users can view own messages" — FOR ALL, USING (conv.user_id = uid)
--   2. "Service role can insert messages" — FOR INSERT, WITH CHECK (true)
--
-- Postgres ORs multiple permissive policies, so policy #2 made every
-- authenticated client able to INSERT a row into ANY conversation —
-- including conversations they do not own. The service-role key
-- already bypasses RLS entirely, so policy #2 was never needed; it
-- was pure attack surface.
--
-- Dropping it leaves policy #1 in place. For INSERT, Postgres falls
-- back to the USING expression as the WITH CHECK when no WITH CHECK
-- is provided, so authenticated INSERTs are now restricted to
-- conversations the user owns. The webhook + send routes continue
-- to work because they use the service-role key.

DROP POLICY IF EXISTS "Service role can insert messages" ON messages;
