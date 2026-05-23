-- ============================================================
-- Idempotent migration — safe to run multiple times.
-- ============================================================

-- Webhook idempotency fix. Meta replays inbound webhook POSTs on its
-- own schedule (signed acks, retries on 5xx, etc.). The original
-- schema put a plain INDEX on `messages.message_id` but no UNIQUE
-- constraint, so a replayed `messages.id` from Meta would insert a
-- second row pointing at the same conversation, double-bump
-- `conversations.unread_count`, and dispatch automations twice.
--
-- This migration:
--   1. Removes any existing duplicates, keeping the row with the
--      lexicographically smaller `id` (UUIDs are not time-ordered,
--      so this is a deterministic-but-arbitrary pick; either copy is
--      semantically identical for a true Meta replay).
--   2. Creates a partial UNIQUE INDEX on `message_id` for rows
--      where `message_id IS NOT NULL`. The partial form keeps
--      pre-Meta-confirm agent-sent rows (NULL message_id until
--      Meta returns the wamid) free of the constraint.
--
-- After this lands, the webhook (src/app/api/whatsapp/webhook/route.ts)
-- switches to upsert(onConflict: 'message_id', ignoreDuplicates: true)
-- so a replay quietly skips the insert and all its side effects.

-- Step 1: collapse duplicates.
DELETE FROM messages a
USING messages b
WHERE a.message_id IS NOT NULL
  AND a.message_id = b.message_id
  AND a.id > b.id;

-- Step 2: partial UNIQUE index. CONCURRENTLY is intentionally not
-- used because some Supabase migration runners disallow it inside a
-- transaction; the regular CREATE is fine for a small-to-medium
-- self-hosted table.
CREATE UNIQUE INDEX IF NOT EXISTS messages_message_id_unique
  ON messages(message_id)
  WHERE message_id IS NOT NULL;
