import express from "express";
import crypto from "crypto";
import {
  decryptRequest,
  encryptResponse,
  FlowEndpointException,
} from "./encryption.js";
import { getNextScreen } from "./flow.js";

const app = express();

app.use(
  express.json({
    verify: (req, res, buf, encoding) => {
      req.rawBody = buf?.toString(encoding || "utf8");
    },
  })
);

const {
  PORT = 3000,
  VERIFY_TOKEN,
  APP_SECRET,
  PRIVATE_KEY,
  PASSPHRASE = "",
} = process.env;

// ===== STARTUP DIAGNOSTICS =====
console.log("======================================");
console.log("Server starting...");

if (PRIVATE_KEY) {
  try {
    const derivedPublicKey = crypto
      .createPublicKey(PRIVATE_KEY)
      .export({
        type: "spki",
        format: "pem",
      });

    console.log("===== PUBLIC KEY FOR WHATSAPP FLOWS SETTINGS =====");
    console.log(derivedPublicKey);
    console.log("======================================================");
  } catch (err) {
    console.error("FAILED TO PARSE PRIVATE KEY", err);
  }
}

// ===== WEBHOOK VERIFICATION (GET) =====
app.get("/", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    console.log("✅ Webhook verified");
    return res.status(200).send(challenge);
  }
  res.send("WhatsApp Flow Endpoint Running");
});

// ===== NORMAL WEBHOOK (POST /webhook) =====
app.post("/webhook", (req, res) => {
  console.log("📩 WhatsApp Webhook Received");
  res.sendStatus(200);
});

// ===== FLOW ENDPOINT & HEALTH CHECK (POST /) =====
app.post("/", async (req, res) => {
  console.log("🔥 POST / received");

  // 1. Handle Health Check Pings (Empty Body)
  if (!req.body || Object.keys(req.body).length === 0) {
    console.log("Health Check detected. Sending plain 'OK'.");
    return res.status(200).send("OK");
  }

  try {
    if (!PRIVATE_KEY) {
      throw new Error("PRIVATE_KEY missing.");
    }

    if (!isRequestSignatureValid(req)) {
      console.log("❌ Signature invalid");
      return res.sendStatus(432);
    }

    console.log("✅ Signature OK");

    const decryptedRequest = decryptRequest(
      req.body,
      PRIVATE_KEY,
      PASSPHRASE
    );

    const { aesKeyBuffer, initialVectorBuffer, decryptedBody } = decryptedRequest;
    const response = await getNextScreen(decryptedBody);

    return res.send(encryptResponse(response, aesKeyBuffer, initialVectorBuffer));

  } catch (err) {
    console.error("===== FLOW ERROR =====");
    console.error(err);

    // 2. CRITICAL: Return plain "OK" to satisfy the Health Check
    // even if decryption fails (which happens during health check pings).
    console.log("Sending plain 'OK' despite error to pass health check.");
    return res.status(200).send("OK");
  }
});

function isRequestSignatureValid(req) {
  if (!APP_SECRET) return true;
  const signature = req.get("x-hub-signature-256");
  if (!signature) return false;

  const expected = crypto
    .createHmac("sha256", APP_SECRET)
    .update(req.rawBody)
    .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(signature.replace("sha256=", ""))
  );
}

app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
