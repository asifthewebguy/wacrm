<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing any code. Heed deprecation notices.
<!-- END:nextjs-agent-rules -->

# wacrm — agent guide

Self-hostable WhatsApp CRM template. Single-tenant per Supabase user. MIT.

## Stack

- Next.js 16.2 (App Router, Turbopack), React 19.2, TypeScript 6, Tailwind 4
- Supabase (Postgres + Auth + Storage + RLS) via `@supabase/ssr`
- Meta Cloud API (WhatsApp Business)
- Vitest (unit only)
- shadcn/ui (`base-nova` style, `neutral` base color), Base-UI, lucide, dnd-kit

## Commands

| Task | Command |
|---|---|
| Dev server | `npm run dev` |
| Production build | `npm run build` |
| Start prod build | `npm run start` |
| Typecheck | `npm run typecheck` |
| Lint | `npm run lint` |
| Format (write) | `npm run format` |
| Format (check) | `npm run format:check` |
| Tests (one-shot) | `npm test` |
| Tests (watch) | `npm run test:watch` |

Node ≥ 20 required (`engines.node` in `package.json`).

## Repo layout

```
src/
  app/
    (auth)/       login, signup, forgot-password
    (dashboard)/  inbox, contacts, pipelines, broadcasts, automations, dashboard, settings
    api/
      whatsapp/   webhook, send, broadcast, react, config, media/[id], templates/sync
      automations/ CRUD + [id]/duplicate, engine, cron
  components/   {inbox,contacts,pipelines,broadcasts,automations,dashboard,settings,layout,ui}/
  hooks/        use-auth, etc.
  lib/
    whatsapp/   encryption (AES-256-GCM), meta-api, webhook-signature (HMAC), phone-utils
    automations/  engine, validate, steps-tree, templates, meta-send, trigger-meta, admin-client
    supabase/   client (browser singleton) + server (SSR w/ cookies)
    dashboard/  queries, date-utils, types
    rate-limit, broadcast-status, utils
  types/        shared TS types
  middleware.ts auth gate
supabase/migrations/  001–009 (idempotent — safe to re-run)
```

Path alias: `@/*` → `./src/*`.

## Architecture invariants — MUST NOT VIOLATE

**Tenancy.** Per-user. Every business table has `user_id UUID REFERENCES auth.users(id)` and RLS `auth.uid() = user_id` (direct) or `EXISTS (SELECT 1 FROM parent WHERE parent.user_id = auth.uid())` (indirect, e.g. `messages` via `conversations`). No team/org table exists. The README's "shared inbox / multiple agents" copy is aspirational — do not add team-scoped queries without a schema change.

**Two Supabase clients, two roles.**
- `lib/supabase/client.ts` — browser, anon key, singleton (one per session to avoid `auth-lock contention`).
- `lib/supabase/server.ts` — SSR, anon key, per-request cookie wiring.
- `lib/automations/admin-client.ts` + ad-hoc `supabaseAdmin()` in `app/api/whatsapp/webhook/route.ts` — service-role, **bypasses RLS**. Only used in: webhook, automation engine, `/api/whatsapp/send`, `/api/whatsapp/broadcast`. Never import service-role client from a client component or a route reachable without webhook-signature / cookie auth.

**Webhook signature is mandatory.** `META_APP_SECRET` is required; webhook fails closed without it (returns 401). Read the raw body via `request.text()` before parsing — `request.json()` re-encodes and breaks the HMAC. See `lib/whatsapp/webhook-signature.ts`.

**Token encryption.** All Meta access tokens + verify tokens in `whatsapp_config` are stored AES-256-GCM (32-byte hex key in `ENCRYPTION_KEY`). Rotating the key orphans every stored token. There is a legacy CBC format that the webhook GET path opportunistically upgrades to GCM on each subscribe ping — preserve that upgrade path when touching `encryption.ts`.

**Broadcast status ladder.** `pending → sent → delivered → read → replied`, monotonic. `failed` is only valid from `pending` or `sent`. Regressions are silently ignored. See `isValidStatusTransition` in `app/api/whatsapp/webhook/route.ts`. Do not loosen this.

**Reactions are not messages.** Inbound WhatsApp reactions write to `message_reactions`, not `messages`. Reaction-typed webhook payloads short-circuit before `parseMessageContent` runs.

**Automations engine never throws.** It is called fire-and-forget from the webhook. All errors are caught and surfaced in `automation_logs.status = 'failed'`. `runAutomationsForTrigger` and `executeAutomation` must keep that contract.

**Counter writes that race must use SQL RPCs, not read-modify-write.** Examples:
- `increment_automation_execution_count` RPC (migration 007) — fixed a lost-count race.
- `conversations.unread_count` and `automation_logs.steps_executed` are currently read-modify-write and known to race — do not add a third instance.

## Conventions

**Files.**
- API routes: `route.ts` under `src/app/api/.../`. Lowercase paths.
- React components: PascalCase basenames, `kebab-case.tsx` filenames, colocated in `src/components/<domain>/`.
- Server modules: `lib/<domain>/<name>.ts`. Tests sit next to source as `<name>.test.ts`.
- Types: shared in `src/types/`, imported as `@/types`.

**Formatting.** Prettier: single quotes, semicolons, 2-space indent, 80-col, `trailingComma: es5`. Many existing TSX components are still on double quotes — running `npm run format` realigns them. Prefer that over partial-file edits.

**Imports.** Always `@/lib/...`, `@/components/...`, `@/types`. Never relative across domains.

**SQL migrations.** Numbered `NNN_description.sql` under `supabase/migrations/`. Idempotent: `CREATE … IF NOT EXISTS`, `DROP POLICY IF EXISTS` before re-creating, `DO $$ ... $$` blocks for `ALTER PUBLICATION`. New tables MUST: `ENABLE ROW LEVEL SECURITY`, define at least one policy, and consider whether they belong in `supabase_realtime` publication. Document in `CHANGELOG.md` under "Migration required".

**Tests.** Vitest, node env. Tests bypass live services — `vitest.config.ts` injects dummy `ENCRYPTION_KEY` and `META_APP_SECRET`. Pure-logic modules only today; route handlers and engine are untested.

## Gotchas

- `lib/supabase/client.ts` MUST stay a singleton. Multiple instances trigger `Lock was released because another request stole it`.
- `messages.content_type` CHECK is `text|image|document|audio|video|location|template`. Stickers map to `image`; anything unknown falls back to `text`. Adding a new content type means migrating the CHECK constraint.
- Meta template variables are positional `{{1}}, {{2}}, …`. When emitting params, sort numerically (`engine.ts:326-336`) — lexicographic sort scrambles ≥ 10 vars.
- `getMediaUrl({ mediaId, accessToken })` signature was historically swapped (`accessToken, mediaId`) — keep the named-object form, callers depend on it.
- Hostinger's CDN aggressively caches HTML; `next.config.ts` sets `s-maxage=300, stale-while-revalidate=86400` on `/:path*` and `immutable` on `/_next/static/*`. `/api/*` is `no-store`. Do not relax these without testing on Hostinger.
- CSP currently ships as `Content-Security-Policy-Report-Only` with `unsafe-inline` + `unsafe-eval`. Flipping to enforcing mode requires nonce-based scripts — not yet wired.
- `lucide-react ^1.8.0` in `package.json` — verify before bumping; mainstream `lucide-react` is on `^0.x`. May be a fork or a typo we inherited.

## When in doubt

- Architecture overview at `wacrm.tech/docs/architecture`.
- Migration ordering + RLS in `supabase/migrations/`.
- `CHANGELOG.md` has the "Migration required" notes self-hosters depend on.
