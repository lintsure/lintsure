import Stripe from "npm:stripe";
const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);
Deno.serve(async (req) => {
  const event = await stripe.webhooks.constructEventAsync(await req.text(), req.headers.get("stripe-signature")!, Deno.env.get("STRIPE_WEBHOOK_SECRET")!);
  return new Response(JSON.stringify({ received: event.type }));
});
