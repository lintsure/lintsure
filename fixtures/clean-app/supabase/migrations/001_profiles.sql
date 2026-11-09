-- Near misses: row level security on, policies limited to the owner, public read only where intended.
create table public.profiles (id uuid primary key, email text);
alter table public.profiles enable row level security;
create policy "own row" on public.profiles for select using (auth.uid() = id);
create table if not exists "posts" (id uuid primary key, published boolean);
alter table "posts" enable row level security;
create table auth.audit_extra (id uuid);
