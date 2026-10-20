# Data API privileges audit — 2026-10-20

## Scope and change

Reviewed all four SQL files in `supabase/`, `src/main.jsx`, `src/interview-calendar.jsx`, `src/lib/supabase.js`, the AI server function, and the deployed admin-delete-user/admin-reset-password Edge Functions (read only). The browser uses Supabase Auth and direct PostgREST calls. The AI function validates a bearer token; this does not require a new service-role table grant. The deployed admin-delete-user function separately checks profile/employee/goal/interview/audit linkage via service-role REST, so those tables need server SELECT only. Auth Admin API deletion itself does not require a table DELETE grant.

The table-creation blocks now grant access **only when the table does not already exist**. Existing tables keep their exact ACLs. Each new table enables RLS and removes inherited default grants to PUBLIC/anon/authenticated/service_role before granting only the operations below. Existing policies, trigger logic and constraints are unchanged. The RLS helper functions receive explicit authenticated EXECUTE so they also work when default function grants are disabled.

| New table | authenticated | anon | service_role Data API |
| --- | --- | --- | --- |
| profiles | SELECT, UPDATE | none | SELECT |
| employees | SELECT, INSERT, UPDATE, DELETE | none | SELECT |
| goals | SELECT, INSERT, UPDATE, DELETE | none | SELECT |
| interviews | SELECT, INSERT, UPDATE, DELETE | none | SELECT |
| audit_logs | SELECT, INSERT | none | SELECT |
| interview_schedules | SELECT, INSERT, UPDATE, DELETE | none | none |

RLS still restricts profile updates and audit reads to admins, and restricts other records by the existing ownership/status policies. Profile creation remains an auth trigger operation. The audit ID is an identity column: inserts were tested without granting sequence USAGE or SELECT. No TRUNCATE, REFERENCES, TRIGGER, ALL TABLES, or default-privilege grant was added. The existing authenticated role is used; app roles such as manager/admin are enforced by RLS, not by new database roles.

## Production application

- **No production SQL or Edge Function deployment was performed.** The active `performance-management` project was inspected using catalog-only SELECT queries.
- Existing tables already have the permissions needed for the current app. The platform change alone requires no re-run of these scripts on that database.
- For a genuinely new environment, use the modified fresh-install schema and then the calendar migration. For a new V4 environment, the modified V4→V4.1 path also includes the new employee grant.
- **Do not re-run `migrate_v4_to_v4_1.sql` on production for this permission change.** It already contains DELETE statements for goals/interviews. No destructive migration was executed during this work.
- These changes do not tighten or expand existing production ACLs. Any later ACL cleanup must be reviewed separately against the current RLS and API usage.

## Missing schema source: reconstruction is not complete

The current app also uses `org_facilities`, `org_departments`, `org_positions`, `role_menu_settings`, and `app_settings`, but their creation SQL is absent from this repository. These are present in the active project with RLS enabled. The checked-in V4.1 schema is therefore **not a complete installer for the current V5 app**. Do not infer that this patch fixes a full V5 preview rebuild.

When their actual DDL is recovered, put the following minimum API grants next to their RLS definitions; do not apply these as a blanket live migration:

| Table | Actual access and minimum future grant |
| --- | --- |
| org_facilities, org_departments | anon SELECT for signup lists of active organizations; authenticated SELECT, INSERT, UPDATE for admin management under existing RLS |
| org_positions | authenticated SELECT, INSERT, UPDATE; no anon call found in current app (the live legacy policy allows anon active-position reads, which was left untouched) |
| role_menu_settings | authenticated SELECT, INSERT, UPDATE (upsert); existing admin RLS for writes |
| app_settings | authenticated SELECT, INSERT, UPDATE (upsert); existing admin RLS for writes; service_role SELECT for admin-delete-user linkage check |

These tables may use sequences; inspect the recovered DDL to grant USAGE on only the sequence used by an actual INSERT when necessary. Do not infer sequence names or grant ALL SEQUENCES. The pre-login organization list is a deliberate anon read path; employee/profile/goal/interview records are not.

## Verification

`tests/data-api-privileges.cjs` executes the actual SQL in PGlite 0.3.14 (PostgreSQL, no network). Four combinations pass: fresh V4.1 and V4→V4.1, each with legacy automatic grants and opt-in defaults. Checks include the full role/operation ACL matrix, RLS enabled, own-team CRUD, cross-team rejection, anonymous rejection and server read-only access (including denied writes), trigger-created profiles, identity audit inserts, denied audit mutation, and byte-for-byte catalog ACL preservation for existing tables. Only the unsupported pgcrypto extension declaration is omitted in this local harness; gen_random_uuid is built in.

Run with `NODE_PATH=<temporary dependency directory>/node_modules node tests/data-api-privileges.cjs`, using `@electric-sql/pglite@0.3.14`.

Live end-to-end testing with each production account was not performed. `CREATE IF NOT EXISTS` historically could accept incompatible existing tables too; these files are versioned setup scripts, not a general schema repair tool.

Reference: https://supabase.com/docs/guides/api/securing-your-api
