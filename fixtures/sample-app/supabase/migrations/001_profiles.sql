-- Planted: a table with no row level security, and a policy that lets everyone in.
create table public.profiles (id uuid primary key, email text);
create table public.notes (id uuid primary key, user_id uuid, body text);
alter table public.notes enable row level security;
create policy "anyone" on public.notes for all using (true);
