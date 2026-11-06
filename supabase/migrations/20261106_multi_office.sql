-- تعدد المكاتب على نفس قاعدة البيانات مع فصل كامل للبيانات
-- مكتب 1 = مكتب ميسان (كل البيانات الحالية)، مكتب 2 = مكتب الرائف

-- 1) جدول المكاتب يقبل أكثر من مكتب
alter table public.office drop constraint if exists office_id_check;
insert into public.office (id, name) values (2, 'مكتب الرائف') on conflict (id) do nothing;
update public.office set name = 'مكتب ميسان' where id = 1;

-- 2) كل مستخدم ومشروع وعنصر محذوف تابع لمكتب (الحالي كله لمكتب ميسان)
alter table public.profiles add column if not exists office_id int not null default 1 references public.office(id);
alter table public.projects add column if not exists office_id int not null default 1 references public.office(id);
alter table public.trash    add column if not exists office_id int not null default 1 references public.office(id);
create index if not exists profiles_office_idx on public.profiles (office_id);
create index if not exists projects_office_idx on public.projects (office_id);
create index if not exists trash_office_idx on public.trash (office_id);

-- 3) دوال المكتب
create or replace function public.my_office() returns int
language sql stable security definer set search_path = '' as $$
  select office_id from public.profiles where id = (select auth.uid()) and status = 'active'
$$;
create or replace function public.project_in_my_office(pid uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.projects where id = pid and office_id = public.my_office())
$$;
create or replace function public.folder_in_my_office(folder text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.projects where id::text = folder and office_id = public.my_office())
      or exists (select 1 from public.trash where project_id::text = folder and office_id = public.my_office())
$$;
revoke execute on function public.my_office(), public.project_in_my_office(uuid), public.folder_in_my_office(text) from anon, public;
grant execute on function public.my_office(), public.project_in_my_office(uuid), public.folder_in_my_office(text) to authenticated;

-- 4) المشروع الجديد والعنصر المحذوف يأخذ مكتب المستخدم تلقائياً
create or replace function public.set_my_office() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is not null then
    new.office_id := coalesce(public.my_office(), new.office_id);
  end if;
  return new;
end $$;
drop trigger if exists projects_set_office on public.projects;
create trigger projects_set_office before insert on public.projects for each row execute function public.set_my_office();
drop trigger if exists trash_set_office on public.trash;
create trigger trash_set_office before insert on public.trash for each row execute function public.set_my_office();

-- 5) السياسات: لا أحد يرى أو يعدّل شيئاً من مكتب آخر
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = (select auth.uid()) or (public.my_role() = 'admin' and office_id = public.my_office()));
drop policy if exists profiles_admin_update on public.profiles;
create policy profiles_admin_update on public.profiles for update to authenticated
  using (public.my_role() = 'admin' and not is_owner and id <> (select auth.uid()) and office_id = public.my_office())
  with check (public.my_role() = 'admin' and not is_owner and office_id = public.my_office());

drop policy if exists office_select on public.office;
create policy office_select on public.office for select to authenticated
  using (public.is_active() and id = public.my_office());
drop policy if exists office_update on public.office;
create policy office_update on public.office for update to authenticated
  using (public.my_role() = 'admin' and id = public.my_office())
  with check (public.my_role() = 'admin' and id = public.my_office());

drop policy if exists projects_select on public.projects;
create policy projects_select on public.projects for select to authenticated
  using (public.is_active() and office_id = public.my_office());
drop policy if exists projects_insert on public.projects;
create policy projects_insert on public.projects for insert to authenticated
  with check (public.my_role() = 'admin' and office_id = public.my_office());
drop policy if exists projects_update on public.projects;
create policy projects_update on public.projects for update to authenticated
  using ((public.has_perm('progress') or public.has_perm('stages')) and office_id = public.my_office())
  with check ((public.has_perm('progress') or public.has_perm('stages')) and office_id = public.my_office());
drop policy if exists projects_delete on public.projects;
create policy projects_delete on public.projects for delete to authenticated
  using (public.my_role() = 'admin' and office_id = public.my_office());

drop policy if exists tests_select on public.test_records;
create policy tests_select on public.test_records for select to authenticated
  using (public.is_active() and public.project_in_my_office(project_id));
drop policy if exists tests_insert on public.test_records;
create policy tests_insert on public.test_records for insert to authenticated
  with check (public.has_perm('tests') and created_by = (select auth.uid()) and public.project_in_my_office(project_id));
drop policy if exists tests_owner_restore on public.test_records;
create policy tests_owner_restore on public.test_records for insert to authenticated
  with check (public.is_owner_user() and public.project_in_my_office(project_id));
drop policy if exists tests_update on public.test_records;
create policy tests_update on public.test_records for update to authenticated
  using (public.has_perm('tests') and public.project_in_my_office(project_id))
  with check (public.has_perm('tests') and public.project_in_my_office(project_id));
drop policy if exists tests_delete on public.test_records;
create policy tests_delete on public.test_records for delete to authenticated
  using (public.has_perm('tests') and public.project_in_my_office(project_id));

drop policy if exists visits_select on public.visits;
create policy visits_select on public.visits for select to authenticated
  using (public.is_active() and public.project_in_my_office(project_id));
drop policy if exists visits_insert on public.visits;
create policy visits_insert on public.visits for insert to authenticated
  with check (public.has_perm('visits') and created_by = (select auth.uid()) and public.project_in_my_office(project_id));
drop policy if exists visits_owner_restore on public.visits;
create policy visits_owner_restore on public.visits for insert to authenticated
  with check (public.is_owner_user() and public.project_in_my_office(project_id));
drop policy if exists visits_update on public.visits;
create policy visits_update on public.visits for update to authenticated
  using (public.has_perm('visits') and public.project_in_my_office(project_id))
  with check (public.has_perm('visits') and public.project_in_my_office(project_id));
drop policy if exists visits_delete on public.visits;
create policy visits_delete on public.visits for delete to authenticated
  using ((public.my_role() = 'admin' or (created_by = (select auth.uid()) and public.is_active())) and public.project_in_my_office(project_id));

drop policy if exists logs_select on public.logs;
create policy logs_select on public.logs for select to authenticated
  using (public.is_active() and public.project_in_my_office(project_id));
drop policy if exists logs_insert on public.logs;
create policy logs_insert on public.logs for insert to authenticated
  with check (public.is_active() and created_by = (select auth.uid()) and public.project_in_my_office(project_id));
drop policy if exists logs_owner_restore on public.logs;
create policy logs_owner_restore on public.logs for insert to authenticated
  with check (public.is_owner_user() and public.project_in_my_office(project_id));

drop policy if exists trash_owner_select on public.trash;
create policy trash_owner_select on public.trash for select to authenticated
  using (public.is_owner_user() and office_id = public.my_office());
drop policy if exists trash_insert on public.trash;
create policy trash_insert on public.trash for insert to authenticated
  with check (public.is_active() and deleted_by = (select auth.uid()) and office_id = public.my_office());
drop policy if exists trash_owner_delete on public.trash;
create policy trash_owner_delete on public.trash for delete to authenticated
  using (public.is_owner_user() and office_id = public.my_office());

-- 6) الملفات: كل مكتب يصل لملفات مشاريعه فقط (المسار يبدأ برقم المشروع)
drop policy if exists test_files_read on storage.objects;
create policy test_files_read on storage.objects for select to authenticated
  using (bucket_id = 'test-files' and public.is_active() and public.folder_in_my_office((storage.foldername(name))[1]));
drop policy if exists test_files_insert on storage.objects;
create policy test_files_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'test-files' and public.has_perm('tests') and public.folder_in_my_office((storage.foldername(name))[1]));
drop policy if exists test_files_delete on storage.objects;
create policy test_files_delete on storage.objects for delete to authenticated
  using (bucket_id = 'test-files' and public.has_perm('tests') and public.folder_in_my_office((storage.foldername(name))[1]));
