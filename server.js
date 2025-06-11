// server.js
const express = require("express");
const session = require("express-session");
const memoryStore = require("memorystore");
const {
  verifyRegistrationResponse,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  generateAuthenticationOptions,
} = require("@simplewebauthn/server");
const { createClient } = require("@supabase/supabase-js");
const base64url = require('base64url');

const app = express();
const MemoryStore = memoryStore(session);

// --- Supabase setup ---
const supabaseUrl = "http://localhost:8000"; // แก้เป็น URL ของคุณ
const supabaseKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyAgCiAgICAicm9sZSI6ICJhbm9uIiwKICAgICJpc3MiOiAic3VwYWJhc2UtZGVtbyIsCiAgICAiaWF0IjogMTY0MTc2OTIwMCwKICAgICJleHAiOiAxNzk5NTM1NjAwCn0.dc_X5iR_VP_qT0zsiyj_I_OZ2T9FtRU2BBNWN8Bu4GE"; // แก้เป็น API Key ของคุณ
const supabase = createClient(supabaseUrl, supabaseKey);

// --- WebAuthn config ---
const port = 3000;
const rpID = "localhost";
const origin = `http://${rpID}`;
const rpName = "WebAuthn Tutorial";
const expectedOrigin = "http://localhost:8100";
const cors = require("cors");

// Allow CORS from your frontend origin
app.use(cors({
  origin: "http://localhost:8100", // frontend origin
  methods: ["GET", "POST", "OPTIONS"],
  credentials: true, // if you want to allow cookies/sessions to be sent
}));
app.use(express.json());
app.use(express.static("./public/"));

app.use(
  session({
    resave: false,
    secret: "secret123",
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      maxAge: 86400000,
    },
    store: new MemoryStore({
      checkPeriod: 86_400_000,
    }),
  })
);

// --- Register begin ---
app.post("/register", async (req, res) => {
  const uname = req.body.username;

  // หา user จาก Supabase
  let { data: user, error } = await supabase
    .from("users")
    .select("*")
    .eq("username", uname)
    .single();

  if (!user) {
    // ถ้าไม่มี user ให้สร้างใหม่
    const { data, error: insertError } = await supabase
      .from("users")
      .insert([{ username: uname }])
      .select()
      .single();

    if (insertError) {
      return res.status(500).send({ error: insertError.message });
    }
    user = data;
  }

  // ดึง passkeys ของ user
  const { data: passKeys = [] } = await supabase
    .from("passkeys")
    .select("*")
    .eq("user_id", user.id);

  const opts = {
    rpID,
    rpName,
    userName: user.username,
    attestationType: "none",
    supportedAlgorithmIDs: [-7, -257],
    authenticatorSelection: {
      residentKey: "discouraged",
    },
    excludeCredentials: passKeys.map((key) => ({
      id: key.id,
      transports: key.transports,
    })),
  };

  const options = await generateRegistrationOptions(opts);

  req.session.challenge = { userId: user.id, options };
  res.send(options);
});

// --- Register complete ---
app.post("/register/complete", async (req, res) => {
  const response = req.body;
  const { options, userId } = req.session.challenge || {};
  console.log("1");
  if (!userId) {
    return res.status(400).send({ error: "No challenge found in session." });
  }

  // ดึง user จาก DB
  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("id", userId)
    .single();

  const { data: passKeys = [] } = await supabase
    .from("passkeys")
    .select("*")
    .eq("user_id", userId);

  const opts = {
    response,
    expectedOrigin,
    expectedRPID: rpID,
    requireUserVerification: false,
    expectedChallenge: options.challenge,
  };

  let verification;
  try {

    console.log("2");
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {

    console.log("3");
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    console.log("Verified:", verified);
    console.log("Registration Info:", registrationInfo);

    const {
      counter,
      credentialID: rawCredentialID,
      credentialBackedUp,
      credentialPublicKey,
      credentialDeviceType,
    } = registrationInfo;
    console.log(rawCredentialID);
    

    const credentialIDBuffer = base64url.toBuffer(rawCredentialID);  // แปลง base64url string เป็น Buffer
    const credentialIDString = base64url.encode(credentialIDBuffer);
    let publicKeyBuffer;
    if (credentialPublicKey instanceof Buffer) {
      publicKeyBuffer = credentialPublicKey;
    } else {
      publicKeyBuffer = Buffer.from(new Uint8Array(credentialPublicKey));
    }

    // ตรวจสอบว่า credentialID นี้เคยถูกใช้หรือยัง
    const existingKey = passKeys.find(
      (key) => Buffer.compare(key.id, credentialID) === 0
    );

    // ถ้ายังไม่มี ให้เพิ่มเข้าไป
    if (!existingKey) {

      console.log("4");
      try {
        const { error } = await supabase.from("passkeys").insert([
          {
            id: credentialIDString,
            user_id: userId,
            counter,
            backedup: credentialBackedUp,
            devicetype: credentialDeviceType,
            transports: response.response.transports,
            credentialpublickey: publicKeyBuffer,
          },
        ]);

        if (error) {

          console.log("5");
          console.error("Insert error:", error);
          return res.status(500).send({ error: "Failed to save passkey." });
        }

      } catch (err) {

        console.log("6");
        console.error("Unexpected error:", err);
        return res.status(500).send({ error: "Unexpected server error." });
      }
    }

  }

  req.session.challenge = undefined;
  res.send({ verified });
});

// --- Login begin ---
app.post("/login", async (req, res) => {
  const uname = req.body.username;

  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("username", uname)
    .single();

  if (!user) {
    return res.status(400).send({ error: "User not found" });
  }

  const { data: passKeys = [] } = await supabase
    .from("passkeys")
    .select("*")
    .eq("user_id", user.id);

  const opts = {
    rpID,
    allowCredentials: passKeys.map((key) => ({
      id: key.id,
      transports: key.transports,
    })),
  };

  const options = await generateAuthenticationOptions(opts);

  req.session.challenge = { userId: user.id, options };
  res.send(options);
});

// --- Login complete ---
app.post("/login/complete", async (req, res) => {
  const { options, userId } = req.session.challenge || {};
  const body = req.body;

  if (!userId) {
    return res.status(400).send({ error: "No challenge found in session." });
  }

  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("id", userId)
    .single();

  const { data: passKeys = [] } = await supabase
    .from("passkeys")
    .select("*")
    .eq("user_id", userId);

  const passKey = passKeys.find((key) => key.id === body.id);

  if (!passKey) {
    return res
      .status(400)
      .send({ error: `Could not find passkey ${body.id} for user ${user.id}` });
  }


  const authenticator = {
    credentialID: Buffer.from(passKey.id, 'base64url'),
    credentialPublicKey: Buffer.from(
      JSON.parse(Buffer.from(passKey.credentialpublickey.slice(2), 'hex').toString()).data
    ),
    counter: passKey.counter,
    transports: passKey.transports || [],
  };

  const opts = {
    response: body,
    expectedOrigin,
    expectedRPID: rpID,
    authenticator,
    requireUserVerification: false,
    expectedChallenge: options.challenge,
  };


  let verification;
  try {
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    console.log("hello");
    console.log(passKey);

    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    await supabase
      .from("passkeys")
      .update({ counter: authenticationInfo.newCounter })
      .eq("id", passKey.id);
  }

  req.session.challenge = undefined;
  res.send({ verified });
});

app.listen(port, () => {
  console.log(`🚀 Server ready on port ${port}`);
});