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

//
// WEBHOOK VERIFICATION
//
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

//
// NORMAL WHATSAPP WEBHOOKS
//
app.post("/webhook", (req, res) => {
  console.log("📩 WhatsApp Webhook");
  console.log(JSON.stringify(req.body, null, 2));

  res.sendStatus(200);
});

//
// WHATSAPP FLOWS ENDPOINT
//
app.post("/", async (req, res) => {
  try {
    if (!PRIVATE_KEY) {
      throw new Error("PRIVATE_KEY environment variable missing.");
    }

    if (!isRequestSignatureValid(req)) {
      return res.sendStatus(432);
    }

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

    console.log("💬 Flow Request");
    console.log(decryptedBody);

    const response = await getNextScreen(decryptedBody);

    console.log("➡️ Flow Response");
    console.log(response);

    return res.send(
      encryptResponse(
        response,
        aesKeyBuffer,
        initialVectorBuffer
      )
    );
  } catch (err) {
    console.error(err);

    if (err instanceof FlowEndpointException) {
      return res.sendStatus(err.statusCode);
    }

    return res.sendStatus(500);
  }
});

function isRequestSignatureValid(req) {
  if (!APP_SECRET) {
    console.warn("APP_SECRET not configured.");
    return true;
  }

  const signature = req.get("x-hub-signature-256");

  if (!signature) {
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
  console.log(`🚀 Server running on port ${PORT}`);
});
