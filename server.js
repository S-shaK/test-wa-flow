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

console.log("PRIVATE_KEY loaded:", !!PRIVATE_KEY);

if (PRIVATE_KEY) {
  console.log("Key length:", PRIVATE_KEY.length);
  console.log("First line:", PRIVATE_KEY.split("\n")[0]);
  console.log(
    "Last line:",
    PRIVATE_KEY.split("\n")[PRIVATE_KEY.split("\n").length - 1]
  );

  try {
    const derivedPublicKey = crypto
      .createPublicKey(PRIVATE_KEY)
      .export({
        type: "spki",
        format: "pem",
      });

    console.log("===== PUBLIC KEY DERIVED FROM RENDER PRIVATE KEY =====");
    console.log(derivedPublicKey);
    console.log("======================================================");
  } catch (err) {
    console.error("FAILED TO PARSE PRIVATE KEY");
    console.error(err);
  }
}

console.log("======================================");

// ===== WEBHOOK VERIFICATION =====

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

// ===== NORMAL WEBHOOK =====

app.post("/webhook", (req, res) => {
  console.log("📩 WhatsApp Webhook");
  console.log(JSON.stringify(req.body, null, 2));
  res.sendStatus(200);
});

// ===== FLOW ENDPOINT =====

app.post("/", async (req, res) => {
  console.log("🔥 POST / received");

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

    const {
      aesKeyBuffer,
      initialVectorBuffer,
      decryptedBody,
    } = decryptedRequest;

    console.log("💬 Decrypted Request:");
    console.log(JSON.stringify(decryptedBody, null, 2));

    const response = await getNextScreen(decryptedBody);

    console.log("👉 Response:");
    console.log(JSON.stringify(response, null, 2));

    return res.send(
      encryptResponse(
        response,
        aesKeyBuffer,
        initialVectorBuffer
      )
    );
  } catch (err) {
    console.error("===== FLOW ERROR =====");
    console.error(err);

    if (err instanceof FlowEndpointException) {
      return res.sendStatus(err.statusCode);
    }

    return res.sendStatus(500);
  }
});

function isRequestSignatureValid(req) {
  if (!APP_SECRET) {
    console.warn("APP_SECRET missing");
    return true;
  }

  const signature = req.get("x-hub-signature-256");

  if (!signature) {
    console.log("No signature header");
    return false;
  }

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
