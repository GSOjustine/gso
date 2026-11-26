# GSO Custodian Inventory System

Inventory management system for the General Services Office (ICS & PAR tracking) backed by Supabase Auth, Postgres with Row Level Security (RLS), and Vercel Serverless Functions.

## Setup

### 1. Supabase Database & Auth
1. Open your Supabase project SQL Editor and run [`supabase/migrations/001_initial_schema.sql`](supabase/migrations/001_initial_schema.sql).
2. In **Authentication → Providers → Email**, disable **Allow new users to sign up** so only admins can provision accounts.
3. Create your first admin user in **Authentication → Users → Add user**, then promote them in SQL Editor:
   ```sql
   update auth.users
   set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{"role":"admin"}'::jsonb
   where email = 'your-admin@gso.gov';

   update public.profiles
   set role = 'admin', is_active = true
   where email = 'your-admin@gso.gov';
   ```

### 2. Vercel Environment Variables
Add these in **Vercel Project Settings → Environment Variables**:
- `SUPABASE_URL` — your Supabase Project URL
- `SUPABASE_ANON_KEY` — your Supabase public `anon` / publishable key
- `SUPABASE_SERVICE_ROLE_KEY` — your Supabase `service_role` secret key (**server-only**, never expose to client)
