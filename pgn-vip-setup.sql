-- Run once in the PGN Supabase SQL Editor.
create table if not exists public.vip_members (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  granted_by uuid not null references auth.users(id),
  starts_at timestamptz not null default now(),
  expires_at timestamptz,
  reason text not null check (reason in ('Founder','Guest','Promotion','Supporter')),
  active boolean not null default true,
  updated_at timestamptz not null default now()
);

alter table public.vip_members enable row level security;

drop policy if exists "Members can view their own VIP" on public.vip_members;
create policy "Members can view their own VIP"
on public.vip_members for select
to authenticated
using (
  user_id = auth.uid()
  or exists (select 1 from public.admin_users where user_id = auth.uid())
);

drop policy if exists "Admins can grant VIP" on public.vip_members;
create policy "Admins can grant VIP"
on public.vip_members for insert
to authenticated
with check (
  exists (select 1 from public.admin_users where user_id = auth.uid())
);

drop policy if exists "Admins can update VIP" on public.vip_members;
create policy "Admins can update VIP"
on public.vip_members for update
to authenticated
using (
  exists (select 1 from public.admin_users where user_id = auth.uid())
)
with check (
  exists (select 1 from public.admin_users where user_id = auth.uid())
);

create index if not exists vip_members_active_expires_idx
on public.vip_members (active, expires_at);
