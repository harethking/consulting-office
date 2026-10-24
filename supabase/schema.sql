-- نظام المكتب الاستشاري — مخطط قاعدة البيانات والصلاحيات
-- يُنفَّذ مرة واحدة على مشروع Supabase جديد.

create extension if not exists pgcrypto;
create extension if not exists pg_net;

-- ===================== الجداول =====================
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  name text not null,
  company text not null default '',
  role text not null default 'staff' check (role in ('admin','staff','contractor')),
  status text not null default 'pending' check (status in ('pending','active','disabled')),
  is_owner boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.office (
  id int primary key default 1 check (id = 1),
  name text not null default '',
  ai_enabled boolean not null default false
);
insert into public.office (id) values (1) on conflict do nothing;

-- أسرار التطبيق (مفتاح Gemini): لا توجد عليها أي سياسة، فلا يقرؤها إلا الخادم
create table public.app_secrets (
  k text primary key,
  v text not null,
  updated_at timestamptz not null default now()
);

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  type text not null check (type in ('complex','gov','invest')),
  client text not null default '',
  location text not null default '',
  color text not null default '#0284c7',
  data jsonb not null default '{}'::jsonb,
  version int not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null
);

create table public.test_records (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects(id) on delete cascade,
  cat_id text not null,
  unit_id text not null default '',
  unit text not null,
  test_date date,
  sample text not null default '',
  lab text not null default '',
  result text not null default '',
  status text not null default 'pending' check (status in ('pending','pass','fail')),
  notes text not null default '',
  files jsonb not null default '[]'::jsonb,
  by_name text not null default '',
  created_by uuid default auth.uid() references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);
create index test_records_project_idx on public.test_records (project_id, created_at);

create table public.visits (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects(id) on delete cascade,
  visit_date date,
  notes text not null,
  open boolean not null default true,
  by_name text not null default '',
  created_by uuid default auth.uid() references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);
create index visits_project_idx on public.visits (project_id, created_at desc);

create table public.logs (
  id bigint generated always as identity primary key,
  project_id uuid not null references public.projects(id) on delete cascade,
  t timestamptz not null default now(),
  by_name text not null default '',
  role text not null default '',
  kind text not null default 'other',
  unit_id text not null default '',
  label text not null default '',
  stage text not null default '',
  from_pct int,
  to_pct int,
  text text not null default '',
  created_by uuid default auth.uid() references auth.users(id) on delete set null
);
create index logs_project_idx on public.logs (project_id, t desc);

-- ===================== دوال الصلاحيات =====================
create or replace function public.my_role() returns text
language sql stable security definer set search_path = '' as $$
  select role from public.profiles where id = (select auth.uid()) and status = 'active'
$$;

create or replace function public.is_active() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles where id = (select auth.uid()) and status = 'active')
$$;

create or replace function public.has_perm(p text) returns boolean
language sql stable security definer set search_path = '' as $$
  select case public.my_role()
    when 'admin' then true
    when 'staff' then p in ('progress','stages','tests','visits')
    when 'contractor' then p in ('visits')
    else false end
$$;

revoke execute on function public.my_role(), public.is_active(), public.has_perm(text) from anon, public;
grant execute on function public.my_role(), public.is_active(), public.has_perm(text) to authenticated;

-- ===================== تفعيل RLS =====================
alter table public.profiles enable row level security;
alter table public.office enable row level security;
alter table public.app_secrets enable row level security;
alter table public.projects enable row level security;
alter table public.test_records enable row level security;
alter table public.visits enable row level security;
alter table public.logs enable row level security;

-- لا وصول للزوار غير المسجلين إطلاقاً
revoke all on all tables in schema public from anon;
revoke all on public.app_secrets from authenticated;

-- profiles: كل مستخدم يقرأ حسابه، والمدير يقرأ الجميع ويعدّل الدور والحالة فقط (عدا المالك ونفسه)
create policy profiles_select on public.profiles for select to authenticated
  using (id = (select auth.uid()) or public.my_role() = 'admin');
revoke insert, update, delete on public.profiles from authenticated;
grant update (role, status) on public.profiles to authenticated;
create policy profiles_admin_update on public.profiles for update to authenticated
  using (public.my_role() = 'admin' and not is_owner and id <> (select auth.uid()))
  with check (public.my_role() = 'admin' and not is_owner);

-- office: القراءة للفعّالين، وتعديل الاسم للمدير
create policy office_select on public.office for select to authenticated using (public.is_active());
revoke insert, update, delete on public.office from authenticated;
grant update (name) on public.office to authenticated;
create policy office_update on public.office for update to authenticated
  using (public.my_role() = 'admin') with check (public.my_role() = 'admin');

-- projects
create policy projects_select on public.projects for select to authenticated using (public.is_active());
create policy projects_insert on public.projects for insert to authenticated with check (public.my_role() = 'admin');
create policy projects_update on public.projects for update to authenticated
  using (public.has_perm('progress') or public.has_perm('stages'))
  with check (public.has_perm('progress') or public.has_perm('stages'));
create policy projects_delete on public.projects for delete to authenticated using (public.my_role() = 'admin');

-- test_records
create policy tests_select on public.test_records for select to authenticated using (public.is_active());
create policy tests_insert on public.test_records for insert to authenticated
  with check (public.has_perm('tests') and created_by = (select auth.uid()));
create policy tests_update on public.test_records for update to authenticated
  using (public.has_perm('tests')) with check (public.has_perm('tests'));
create policy tests_delete on public.test_records for delete to authenticated using (public.has_perm('tests'));

-- visits
create policy visits_select on public.visits for select to authenticated using (public.is_active());
create policy visits_insert on public.visits for insert to authenticated
  with check (public.has_perm('visits') and created_by = (select auth.uid()));
create policy visits_update on public.visits for update to authenticated
  using (public.has_perm('visits')) with check (public.has_perm('visits'));
create policy visits_delete on public.visits for delete to authenticated
  using (public.my_role() = 'admin' or (created_by = (select auth.uid()) and public.is_active()));

-- logs: إضافة فقط، بدون تعديل أو حذف
create policy logs_select on public.logs for select to authenticated using (public.is_active());
create policy logs_insert on public.logs for insert to authenticated
  with check (public.is_active() and created_by = (select auth.uid()));
revoke update, delete on public.logs from authenticated;

-- ===================== ملفات الفحوصات =====================
insert into storage.buckets (id, name, public, file_size_limit)
values ('test-files', 'test-files', false, 20971520)
on conflict (id) do nothing;

create policy test_files_read on storage.objects for select to authenticated
  using (bucket_id = 'test-files' and public.is_active());
create policy test_files_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'test-files' and public.has_perm('tests'));
create policy test_files_delete on storage.objects for delete to authenticated
  using (bucket_id = 'test-files' and public.has_perm('tests'));

-- ===================== التحديث اللحظي =====================
do $$
declare t text;
begin
  foreach t in array array['projects','test_records','visits','logs'] loop
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;

-- ===================== إضافات لاحقة =====================
-- نسبة الإنجاز الكلي للمشروع (تُحدَّث عند كل حفظ)
alter table public.projects add column if not exists progress numeric(6,2) not null default 0;

-- محادثات المهندس الذكي: كل مستخدم يرى محادثاته فقط
create table if not exists public.ai_messages (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  project_id uuid references public.projects(id) on delete cascade,
  role text not null check (role in ('user','ai')),
  text text not null,
  created_at timestamptz not null default now()
);
create index if not exists ai_messages_user_idx on public.ai_messages (user_id, project_id, created_at desc);
alter table public.ai_messages enable row level security;
revoke all on public.ai_messages from anon;
create policy ai_msg_select on public.ai_messages for select to authenticated
  using (user_id = (select auth.uid()) and public.is_active());
create policy ai_msg_insert on public.ai_messages for insert to authenticated
  with check (user_id = (select auth.uid()) and public.is_active());
create policy ai_msg_delete on public.ai_messages for delete to authenticated
  using (user_id = (select auth.uid()));
revoke update on public.ai_messages from authenticated;
