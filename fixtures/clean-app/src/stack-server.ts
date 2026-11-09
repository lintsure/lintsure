// Near miss: the service-role key in server-only code is fine.
const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);
