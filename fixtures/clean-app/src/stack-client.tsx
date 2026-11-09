"use client";
// Near misses: keys that are public by design.
const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
const stripe = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;
const maps = process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY;
