"use client";
// Planted: secrets that reach the browser.
const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);
const stripe = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;
const openai = process.env.NEXT_PUBLIC_OPENAI_API_KEY;
