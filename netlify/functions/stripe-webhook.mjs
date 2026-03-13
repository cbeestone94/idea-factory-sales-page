// Stripe webhook → Kit (ConvertKit) subscriber + tag
// Triggered on checkout.session.completed

import crypto from "crypto";

export default async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const body = await req.text();
  const sig = req.headers.get("stripe-signature");
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  // Verify Stripe signature
  if (!verifyStripeSignature(body, sig, webhookSecret)) {
    console.error("Invalid Stripe signature");
    return new Response("Invalid signature", { status: 400 });
  }

  const event = JSON.parse(body);

  if (event.type !== "checkout.session.completed") {
    return new Response(JSON.stringify({ received: true }), { status: 200 });
  }

  const session = event.data.object;
  const email = session.customer_details?.email;
  const name = session.customer_details?.name;

  if (!email) {
    console.error("No email found in checkout session");
    return new Response("No email", { status: 400 });
  }

  // Add subscriber to Kit with tag
  try {
    await addToKit(email, name);
    console.log(`Added ${email} to Kit with idea-factory-buyer tag`);
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  } catch (err) {
    console.error("Kit API error:", err.message);
    return new Response("Kit API error", { status: 500 });
  }
};

async function addToKit(email, name) {
  const apiKey = process.env.KIT_API_KEY;
  const tagId = process.env.KIT_TAG_ID;

  const firstName = name ? name.split(" ")[0] : "";

  const res = await fetch(`https://api.convertkit.com/v3/tags/${tagId}/subscribe`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      api_key: apiKey,
      email,
      first_name: firstName,
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Kit API ${res.status}: ${text}`);
  }

  return res.json();
}

function verifyStripeSignature(payload, header, secret) {
  if (!header || !secret) return false;

  const parts = header.split(",").reduce((acc, part) => {
    const [key, value] = part.split("=");
    acc[key] = value;
    return acc;
  }, {});

  const timestamp = parts.t;
  const signature = parts.v1;

  if (!timestamp || !signature) return false;

  // Reject if timestamp is older than 5 minutes
  const now = Math.floor(Date.now() / 1000);
  if (now - parseInt(timestamp) > 300) return false;

  const signedPayload = `${timestamp}.${payload}`;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(signedPayload)
    .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(signature, "hex"),
    Buffer.from(expected, "hex")
  );
}

export const config = {
  path: "/api/stripe-webhook",
};
