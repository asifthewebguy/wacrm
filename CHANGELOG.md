# Changelog

User-visible changes in `wacrm`. Self-hosters: when pulling an update,
check this file for any **migration required** notes and apply the
matching SQL files from `supabase/migrations/` against your Supabase
project before restarting the app.

Versions follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

- Chat actions in the inbox: emoji reactions, reply-with-quote, and
  copy-text on individual messages. Hover on desktop, long-press on
  touch. Outbound reactions and replies forward to WhatsApp via the
  Cloud API; inbound reactions and swipe-replies from customers arrive
  through the webhook and appear in real time.
- SSRF defence for `send_webhook` automation steps. User-supplied
  URLs are now refused at activation time (literal-IP rejection) and
  at execution time (DNS resolution → private-CIDR check). Blocks
  RFC1918, loopback, link-local, cloud metadata (169.254.169.254),
  IPv6 ULA, and IPv6 link-local. See `src/lib/automations/url-safety.ts`.
  Residual DNS-rebinding risk is documented in that module.

### Migration required

- Apply `supabase/migrations/009_message_actions.sql` to your Supabase
  project. It adds `messages.reply_to_message_id` and the new
  `message_reactions` table (with RLS and realtime). The migration is
  idempotent — safe to re-run.
- Apply `supabase/migrations/010_fix_messages_insert_rls.sql`. This
  drops the overly-permissive `Service role can insert messages` RLS
  policy on `public.messages`. The original policy ORed with the
  owner-scoped policy and allowed any authenticated client to INSERT
  messages into conversations they did not own. The service-role key
  bypasses RLS anyway, so dropping the policy does not change
  webhook/send routes.
- Apply `supabase/migrations/011_messages_message_id_unique.sql`. This
  collapses any existing duplicate rows on `messages.message_id`, then
  installs a partial UNIQUE index. Required for the webhook's new
  upsert-based idempotency check — a Meta webhook replay now silently
  skips the insert and the side-effects (unread_count++, automation
  dispatch) instead of double-firing.

### Changed

- The webhook no longer stores inbound customer reactions as fake text
  messages. They are written to `message_reactions` instead, so any
  custom queries that counted reactions as messages will need updating.
- The webhook now uses `upsert(ignoreDuplicates: true, onConflict: 'message_id')`
  for inbound messages. On a Meta replay, the duplicate insert is
  refused at the DB layer and the webhook short-circuits before
  bumping `conversations.unread_count` or dispatching automations.

### Security

- Dropped the `messages` RLS policy `Service role can insert messages`
  (`FOR INSERT WITH CHECK (true)`) — see migration 010 above. Closes
  a cross-tenant message-injection hole that existed since the
  initial schema.
- Added private-CIDR + cloud-metadata blocking on outbound HTTP for
  the `send_webhook` automation step. See migration notes + the
  `url-safety.ts` module.
