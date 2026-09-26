-- Run once in the PGN Supabase SQL Editor.
-- One authoritative admin check is shared by the dashboard, VIP and photos.
-- The email fallback keeps the founding PGN admin working even if the
-- admin_users row has not been created yet.
create or replace function public.is_pgn_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    auth.uid() is not null
    and (
      lower(coalesce(auth.jwt() ->> 'email', '')) = 'pgnhelp@gmail.com'
      or exists (
        select 1 from public.admin_users a
        where a.user_id = auth.uid()
      )
    );
$$;

revoke all on function public.is_pgn_admin() from public;
grant execute on function public.is_pgn_admin() to authenticated;

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
  or public.is_pgn_admin()
);

drop policy if exists "Admins can grant VIP" on public.vip_members;
create policy "Admins can grant VIP"
on public.vip_members for insert
to authenticated
with check (
  public.is_pgn_admin()
);

drop policy if exists "Admins can update VIP" on public.vip_members;
create policy "Admins can update VIP"
on public.vip_members for update
to authenticated
using (
  public.is_pgn_admin()
)
with check (
  public.is_pgn_admin()
);

create index if not exists vip_members_active_expires_idx
on public.vip_members (active, expires_at);

-- Profile-photo access fix.
-- Keep the bucket private; authenticated members receive short-lived signed URLs.
insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', false)
on conflict (id) do update set public = false;

drop policy if exists "PGN members can view permitted avatars" on storage.objects;
create policy "PGN members can view permitted avatars"
on storage.objects for select
to authenticated
using (
  bucket_id = 'avatars'
  and (
    -- A member can always view their own uploaded photo.
    (storage.foldername(name))[1] = auth.uid()::text
    -- Admins can review every profile photo, including profiles awaiting approval.
    or public.is_pgn_admin()
    -- Members can view photos belonging to approved, active profiles.
    or exists (
      select 1 from public.profiles p
      where p.id::text = (storage.foldername(name))[1]
        and p.pilot_approved = true
        and p.active = true
    )
  )
);

drop policy if exists "PGN members can upload their own avatar" on storage.objects;
create policy "PGN members can upload their own avatar"
on storage.objects for insert
to authenticated
with check (
  bucket_id = 'avatars'
  and (storage.foldername(name))[1] = auth.uid()::text
);

drop policy if exists "PGN members can update their own avatar" on storage.objects;
create policy "PGN members can update their own avatar"
on storage.objects for update
to authenticated
using (
  bucket_id = 'avatars'
  and (storage.foldername(name))[1] = auth.uid()::text
)
with check (
  bucket_id = 'avatars'
  and (storage.foldername(name))[1] = auth.uid()::text
);

drop policy if exists "PGN members can delete their own avatar" on storage.objects;
create policy "PGN members can delete their own avatar"
on storage.objects for delete
to authenticated
using (
  bucket_id = 'avatars'
  and (storage.foldername(name))[1] = auth.uid()::text
);
