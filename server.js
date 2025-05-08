import multer from 'multer';
import cloudinary from './cloudinaryConfig.js';
import cors from 'cors';
import fs from 'fs';
import dotenv from 'dotenv';

// We no longer need groupTextElementsSpatially if extracting directly from image
// import { groupTextElementsSpatially } from './utils.js';

dotenv.config();

import express from 'express';

import { fileURLToPath } from "url";
import path from "path";

// We no longer need the Google Vision client if extracting directly from image
// import vision from '@google-cloud/vision';

import JSON5 from 'json5';


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const keyFilePath = path.join(__dirname, './persistent/keys/vision-ai-455010-6d2a9944437b.json'); // Ensure this path is correct for your service account key

process.env.GOOGLE_APPLICATION_CREDENTIALS = keyFilePath;

if (!fs.existsSync(keyFilePath)) {
  console.error('❌ Key file not found:', keyFilePath);
}
else {
  console.log('✅ Key file found:', keyFilePath);
}

// No longer need to parse credentials here unless used elsewhere
// const credentials = JSON.parse(fs.readFileSync(keyFilePath, 'utf8'));


console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID);
console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET);


import { VertexAI } from '@google-cloud/vertexai';

const vertexAI = new VertexAI({project: 'vision-ai-455010', location: 'us-central1'}); // Replace with your project and location

console.log('✅ VertexAI client initialized in server.js');


// Load private key for Apple authentication (keeping this as it seems unrelated to image extraction)
const privateKeyPath = path.join(__dirname, "./persistent/keys/AuthKey_6YK9NFRYH9.p8"); // Path to your .p8 key file
const privateKey = fs.readFileSync(privateKeyPath, "utf8");

// We no longer need the Google Vision client instance
// const client = new vision.ImageAnnotatorClient({
//   keyFilename: path.join(__dirname, './persistent/keys/vision-ai-455010-6d2a9944437b.json'), // Replace with your key file path
// });


import { format } from 'path';
import db from './connection.js';

import cookieParser from 'cookie-parser';
import bodyParser from'body-parser';

import AppleSigninAuth from 'apple-signin-auth';

import OpenAI from "openai";
const openai = new OpenAI(); // Keeping OpenAI client as it's used in chatgptExtractProducts route

import download from 'image-downloader';

export const app = express();


import jwt from 'jsonwebtoken';

import webPush from 'web-push';

import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as AppleStrategy } from 'passport-apple';

import session from 'express-session';
import axios from "axios";

app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Supports form data parsing


app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy",
    "script-src 'self' https://singular-catfish-deciding.ngrok-free.app https://www.apple.com https://appleid.cdn-apple.com https://idmsa.apple.com https://gsa.apple.com https://idmsa.apple.com.cn https://signin.apple.com;"
  );
  next();
});

app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true ,

  cookie: {
    maxAge: 5 * 60 * 1000, // Set session duration
    secure: process.env.NODE_ENV === 'production', // Set secure cookies in production
  }

}));


passport.use(
  new GoogleStrategy(
      {
          clientID: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          callbackURL: "http://localhost:3000/auth/google/callback",
          passReqToCallback: true,
      },
      (req, accessToken, refreshToken, profile, done) => {
          return done(null, profile);
      }
  )
);


// Serialize and deserialize user (use sessions)
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Initialize passport and session middleware
app.use(passport.initialize());
app.use(passport.session());


// Apple Sign-In Route (keeping these as they are authentication related)
app.get(
  "/auth/apple222",
  passport.authenticate("apple", { scope: ["email", "name"] }),
  (req, res) => {
    console.log("🍏 Apple OAuth Callback Triggered");
  }
);

app.get("/auth/apple44444", (req, res) => {
  const appleRedirectUrl = `https://appleid.apple.com/auth/authorize?response_type=code%20id_token&client_id=${process.env.APPLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.APPLE_CALLBACK_URL)}&scope=name%20email&response_mode=form_post`;
  res.redirect(appleRedirectUrl);
});


const generateAppleClientSecret = () => {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: process.env.APPLE_TEAM_ID,
      iat: now,
      exp: now + 15777000, // Token valid for 6 months
      aud: "https://appleid.apple.com",
      sub: process.env.APPLE_CLIENT_ID,
    },
    privateKey,
    {
      algorithm: "ES256",
      keyid: process.env.APPLE_KEY_ID,
    }
  );
};


app.post("/auth/apple", async (req, res) => {
  try {
    const { code } = req.body;
    const clientSecret = generateAppleClientSecret();
    const appleResponse = await AppleSigninAuth.getAuthorizationToken(code, {
      clientID: process.env.APPLE_CLIENT_ID,
      clientSecret: clientSecret,
      redirectURI: process.env.APPLE_CALLBACK_URL,
    });
    const decodedToken = jwt.decode(appleResponse.id_token);
    res.json({ user: decodedToken, accessToken: appleResponse.access_token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Apple Sign-in failed" });
  }
});

app.post("/auth/apple/callback", async (req, res) => {
  try {
    console.log("🍏 Apple OAuth Callback Triggered");
    const { code, id_token } = req.body;

    if (!code && !id_token) {
      console.error("❌ No authorization code or ID token received.");
      return res.status(400).json({ error: "Missing Apple authorization data" });
    }

    let decodedToken;
    if (id_token) {
      decodedToken = jwt.decode(id_token);
    } else {
      const clientSecret = generateAppleClientSecret();
      const appleResponse = await axios.post("https://appleid.apple.com/auth/token", null, {
        params: {
          client_id: process.env.APPLE_CLIENT_ID,
          client_secret: clientSecret,
          code: code,
          grant_type: "authorization_code",
          redirect_uri: process.env.APPLE_CALLBACK_URL,
        },
      });

      if (!appleResponse.data.id_token) {
        console.error("❌ Failed to retrieve Apple ID token.");
        return res.status(400).json({ error: "Failed to authenticate with Apple" });
      }
      decodedToken = jwt.decode(appleResponse.data.id_token);
    }

    if (!decodedToken) {
      console.error("❌ Failed to decode Apple ID token.");
      return res.status(400).json({ error: "Invalid Apple ID token" });
    }

    const appleId = decodedToken.sub;
    let email = decodedToken.email || null;

    console.log(`🍏 Received AppleID: ${appleId}, Email: ${email || "No email provided"}`);

    const checkQuery = `SELECT userId, email FROM users WHERE userId = ? OR email = ?`;
    db.query(checkQuery, [appleId, email], (err, results) => {
      if (err) {
        console.error("❌ Database error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (results.length > 0) {
        const existingUser = results[0];
        console.log(`✅ Existing user found: userId=${existingUser.userId}, email=${existingUser.email || "No email"}`);

        if (!existingUser.email && email) {
          const updateQuery = `UPDATE users SET email = ? WHERE userId = ?`;
          db.query(updateQuery, [email, existingUser.userId], (updateErr) => {
            if (updateErr) {
              console.error("❌ Error updating email:", updateErr);
              return res.status(500).json({ error: "Failed to update email" });
            }
            console.log(`✅ Email updated for userId=${existingUser.userId}`);
          });
        }

        const token = jwt.sign(
          { userId: existingUser.userId, email: existingUser.email || email },
          process.env.TOKEN_SECRET,
          { expiresIn: "7d" }
        );

        res.cookie("jwt", token, {
          httpOnly: true,
          secure: true,
          sameSite: "None",
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        return res.redirect(`${process.env.FRONTEND_URL}?loginSuccess=true`);
      } else {
        console.log(`🆕 New user detected, inserting: ${email || "No email provided"}`);
        const insertQuery = `INSERT INTO users (userName, email) VALUES (?, ?)`;
        db.query(insertQuery, [appleId, email], (insertErr) => {
          if (insertErr) {
            console.error("❌ Error inserting new user:", insertErr);
            return res.status(500).json({ error: "Failed to insert new user" });
          }

          console.log(`✅ New user inserted: AppleID=${appleId}, Email=${email || "No email"}`);
          const token = jwt.sign(
            { userId: appleId, email },
            process.env.TOKEN_SECRET,
            { expiresIn: "7d" }
          );

          res.cookie("jwt", token, {
            httpOnly: true,
            secure:true,
            sameSite: "None",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          });

          return res.redirect(`${process.env.FRONTEND_URL}?loginSuccess=true`);
        });
      }
    });
  } catch (error) {
    console.error("❌ Apple OAuth Error:", error);
    return res.status(500).json({ error: "Apple authentication failed" });
  }
});


app.post("/auth/apple/callback121212", async (req, res) => {
  try {
    console.log("🍏 Apple OAuth Callback Triggered");
    const { code, id_token } = req.body;

    if (!code && !id_token) {
      console.error("❌ No authorization code or ID token received.");
      return res.status(400).json({ error: "No authorization code provided" });
    }

    const clientSecret = generateAppleClientSecret();
    const appleResponse = await AppleSigninAuth.getAuthorizationToken(code, {
      clientID: process.env.APPLE_CLIENT_ID,
      clientSecret: clientSecret,
      redirectURI: process.env.APPLE_CALLBACK_URL,
    });
    const decodedToken = jwt.decode(appleResponse.id_token);
    const appleId = decodedToken.sub;
    const email = decodedToken.email || null;
    res.json({ user: decodedToken, accessToken: appleResponse.access_token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Apple Sign-in failed" });
  }
});


app.post("/auth/apple/callback33", async (req, res) => {
  try {
      console.log("🍏 Apple OAuth Callback Triggered");
      const { id_token } = req.body;
      if (!id_token) {
          console.error("❌ No ID token received.");
          return res.status(400).json({ error: "Missing ID token" });
      }

      const appleKeys = await axios.get("https://appleid.apple.com/auth/keys");
      const applePublicKeys = appleKeys.data.keys;
      const decodedHeader = jwt.decode(id_token, { complete: true });
      if (!decodedHeader) {
          console.error("❌ Failed to decode Apple ID token.");
          return res.status(400).json({ error: "Invalid ID token" });
      }

      const key = applePublicKeys.find(k => k.kid === decodedHeader.header.kid);
      if (!key) {
          console.error("❌ No matching Apple key found.");
          return res.status(400).json({ error: "Invalid Apple key" });
      }

      const verifiedPayload = jwt.verify(id_token, jwt.jwkToPem(key), { algorithms: ["RS256"] });
      console.log("✅ Apple ID Token Verified:", verifiedPayload);

      const appleId = verifiedPayload.sub;
      let email = verifiedPayload.email || null;

      console.log(`🍏 Received AppleID: ${appleId}, Email: ${email || "No email provided"}`);

      const checkQuery = `SELECT userId, email FROM users WHERE userId = ? OR email = ?`;
      db.query(checkQuery, [appleId, email], (err, results) => {
          if (err) {
              console.error("❌ Database error:", err);
              return res.status(500).json({ error: "Database error" });
          }

          if (results.length > 0) {
              const existingUser = results[0];
              console.log(`✅ Existing user found: userId=${existingUser.userId}, email=${existingUser.email || "No email"}`);

              if (!existingUser.email && email) {
                  const updateQuery = `UPDATE users SET email = ? WHERE userId = ?`;
                  db.query(updateQuery, [email, existingUser.userId], (updateErr) => {
                      if (updateErr) {
                          console.error("❌ Error updating email:", updateErr);
                          return res.status(500).json({ error: "Failed to update email" });
                      }
                      console.log(`✅ Email updated for userId=${existingUser.userId}`);
                  });
              }

              const token = jwt.sign(
                  { userId: existingUser.userId, email: existingUser.email || email },
                  process.env.TOKEN_SECRET,
                  { expiresIn: "7d" }
              );

              res.cookie("jwt", token, {
                  httpOnly: true,
                  secure: true,
                  sameSite: "None",
                  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
              });

              return res.redirect(`${process.env.FRONTEND_URL}?loginSuccess=true`);
          } else {
              console.log(`🆕 New user detected, inserting: ${email || "No email provided"}`);
              const insertQuery = `INSERT INTO users (userId, email) VALUES (?, ?)`;
              db.query(insertQuery, [appleId, email], (insertErr) => {
                  if (insertErr) {
                      console.error("❌ Error inserting new user:", insertErr);
                      return res.status(500).json({ error: "Failed to insert new user" });
                  }

                  console.log(`✅ New user inserted: AppleID=${appleId}, Email=${email || "No email"}`);
                  const token = jwt.sign({ userId: appleId, email }, process.env.TOKEN_SECRET, { expiresIn: "7d" });

                  res.cookie("jwt", token, {
                      httpOnly: true,
                      secure: true,
                      sameSite: "None",
                      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
                  });

                  return res.redirect(`${process.env.FRONTEND_URL}?loginSuccess=true`);
              });
          }
      });
  } catch (error) {
      console.error("❌ Apple OAuth Error:", error);
      return res.status(500).json({ error: "Apple authentication failed" });
  }
});


// Specify the model you want to use (e.g., Gemini 1.5 Pro)
const model = 'gemini-1.5-pro-002';

// Access the generative model
const generativeModel = vertexAI.getGenerativeModel({
    model: model,
    generation_config: {
        temperature: 0.2,
        topP: 0.8,
        topK: 40,
        maxOutputTokens: 4096 // Increased max output tokens for potentially larger JSON
    },
});


// Apple Callback Route (keeping this)
const corsOptions = {
  origin: [process.env.FRONTEND_URL, process.env.FRONTEND_URL2,
    'http://localhost:5173',
    'http://192.168.1.*', // Allow local network IPs
    'http://localhost:5173/dashboard',
    'https://www.meniven.com',
    'https://qg048c0c0wos4o40gos4k0kc.128.140.43.244.sslip.io',
    'https://singular-catfish-deciding.ngrok-free.app'] , // Replace with your frontend's origin
  credentials: true,
  origin: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

console.log('corsOptions:', corsOptions);

app.use(cors(corsOptions));
app.use(cookieParser());
app.use(bodyParser.json());


import authRoutes from "./routes/authRoutes.js";
app.use("/auth", authRoutes);


const verifyToken = (req, res, next) => {
  const token = req.cookies.jwt;
  if (!token) {
    return res.status(403).send('A token is required for authentication');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
  } catch (err) {
    return res.status(401).send('Invalid token');
  }
  return next();
};


app.post('/dashboardLogin', (req, res) => {
  const { username, password } = req.body;
  console.log('🔒 Login attempt:', username);
  console.log('🔒 Password:' , password) ;
  const query = 'SELECT * FROM users WHERE userName = ? AND password = ?';
  db.query(query, [username, password], (err, results) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    if (results.length > 0) {
      const user = results[0];
      console.log('🔒 User found:', user.userName);
      res.json({ user: { userId: user.userId, userName: user.userName } });
    } else {
      res.status(401).json({ message: 'Invalid username or password' });
    }
  });
});

app.get("/check-session",  (req, res) => {
  const token = req.cookies.jwt;
  if (!token) {
      return res.json({ isLoggedIn: false, userId: null });
  }

  try {
      const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
      const query = `SELECT userId, email FROM users WHERE userId = ?`;
      db.query(query, [decoded.userId], (err, results) => {
          if (err) {
              console.error("❌ Error retrieving user:", err);
              return res.status(500).json({ isLoggedIn: false, userId: null });
          }
          if (results.length === 0) {
              console.warn("⚠️ User not found in database");
              return res.json({ isLoggedIn: false, userId: null });
          }
          res.json({ isLoggedIn: true, userId: results[0].userId, email: results[0].email });
      });
  } catch (error) {
      console.error("❌ Invalid JWT:", error.message);
      res.clearCookie("jwt");
      return res.json({ isLoggedIn: false, userId: null });
  }
});


app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));


app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/" }), (req, res) => {
  console.log("Google OAuth Callback Triggered");
  console.log("Cookies received:", req.cookies);
  const token = req.cookies.jwt;

  if (!token) {
      console.error("⚠️ No JWT token found in cookies.");
      return res.status(400).json({ error: "JWT token is missing" });
  }

  try {
      console.log("Using TOKEN_SECRET for verification:", process.env.TOKEN_SECRET);
      const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
      console.log("✅ Decoded Token:", decoded);
      const userId = decoded.userId;
      const email = req.user.emails[0].value;
      console.log(`Updating email for userId: ${userId}, New Email: ${email}`);
      const query = `UPDATE users SET email = ? WHERE userId = ?`;
      db.query(query, [email, userId], (err, result) => {
          if (err) {
              console.error("❌ Error updating user email:", err);
              return res.status(500).json({ error: "Database error" });
          }
          res.redirect(`${process.env.FRONTEND_URL}?emailUpdated=true`);
      });
  } catch (err) {
      console.error("❌ JWT Verification Error:", err.message);
      return res.status(401).json({ error: "Invalid token" });
  }
});


app.get("/auth/google/callback3", passport.authenticate("google", { failureRedirect: "/" }), (req, res) => {
  console.log("Cookies received:", req.cookies);
  const token = req.cookies.jwt;
  console.log("Token received:", token);
  const email = req.user.emails[0].value;
  const googleId = req.user.id;
  const name = req.user.displayName;

  if (!token) {
      return res.status(400).json({ error: "JWT token is missing" });
  }

  console.log("Received Token:", token);
  console.log("Decoded Token:", jwt.decode(token));

  try {
    console.log("JWT Secret Key:", process.env.TOKEN_SECRET);
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
    console.log("Decoded Token:", decoded);
    const userId = decoded.userId;
    console.log("User ID from JWT:", userId);
    const query = `UPDATE users SET email = ? WHERE userId = ?`;
    db.query(query, [email, userId], (err, result) => {
        if (err) {
            console.error("Error updating user email:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.redirect(`${process.env.FRONTEND_URL}?emailUpdated=true`);
    });
  } catch (err) {
    console.error("❌ JWT Verification Error:", err.message);
    return res.status(401).json({ error: "Invalid token" });
  }
});


const SECRET_KEY = 'AAAA-BBBB-CCCC-DDDD-EEEE'; // Consider moving this to environment variables

const upload = multer({ dest: 'uploads/' }); // Define upload middleware


// **UPDATED** /extract-text route to use Gemini 1.5 Pro directly on the image
app.post('/extract-text', upload.single('image'), async (req, res) => {
  console.log('🔍 Extracting data from image using Gemini 1.5 Pro…');

  // Assuming userId is available from authentication middleware or session
  // Replace with your actual way of getting userId
  const userId = req.user ? req.user.userId : 1; // Example: Get from req.user if using auth middleware, default to 1

  const { saleEndDate, storeId } = req.body;
  console.log('Sale End Date:', saleEndDate);
  console.log('Store ID:', storeId);
  console.log('User ID:', userId); // Log userId
  console.log('Image file:', req.file);

  try {
    if (!req.file) {
      console.error('❌ No image file provided.');
      return res.status(400).json({ message: 'No image file provided.' });
    }

    const imagePath = req.file.path;
    console.log(`🛣️  Local path: ${imagePath}`);

    // 1️⃣ Upload to Cloudinary to get a public URL
    console.log('▶️  Uploading to Cloudinary…');
    const uploadedImage = await cloudinary.uploader.upload(imagePath, {
      folder: 'uploads',
      public_id: req.file.originalname.split('.')[0],
      resource_type: 'image',
      overwrite: true,
    });
    const imageUrl = uploadedImage.secure_url;
    console.log('✅ Uploaded URL:', imageUrl);

    // 2️⃣ Format and Extract data using Gemini 1.5 Pro directly from the image URL
    console.log('▶️  Formatting and extracting data from image using Gemini 1.5 Pro…');
    // Pass the image URL directly to formatDataToJson
    const jsonText = await formatDataToJson(imageUrl, imageUrl, saleEndDate, storeId, userId); // Pass imageUrl as data source and metadata
    console.log('✅ Formatted JSON from Gemini:', jsonText);

    // 3️⃣ Cleanup
    fs.unlinkSync(imagePath);
    console.log('✅ Deleted temp file');

    // 4️⃣ Respond
    // Respond with the formatted JSON data
    return res.json({ jsonText, imageUrl });

  } catch (err) {
    console.error('❌ Error in /extract-text route:', err);
    // Ensure temp file is deleted even on error
    if (req.file && req.file.path) {
        fs.unlinkSync(req.file.path);
    }
    return res.status(500).json({
      message: 'Failed to extract data from image using Gemini.',
      error: err.message
    });
  }
});


// Keeping other extract-text routes for now, but they are not using the new Gemini image analysis
app.post('/extract-text0000', upload.single('image'), async (req, res) => {
  console.log('🔍 Extracting text from image…');

  const { saleEndDate, storeId } = req.body;
  console.log('Sale End Date:', saleEndDate);
  console.log('Store ID:', storeId);
  console.log('Image file:', req.file);

  try {
    if (!req.file) {
      console.error('❌ No image file provided.');
      return res.status(400).json({ message: 'No image file provided.' });
    }

    const imagePath = req.file.path;
    console.log(`🛣️  Local path: ${imagePath}`);

    console.log('▶️  Uploading to Cloudinary…');
    const uploadedImage = await cloudinary.uploader.upload(imagePath, {
      folder: 'uploads',
      public_id: req.file.originalname.split('.')[0],
      resource_type: 'image',
      overwrite: true,
    });
    const imageUrl = uploadedImage.secure_url;
    console.log('✅ Uploaded URL:', imageUrl);

    // 3️⃣ OCR with Google Vision - Using DOCUMENT_TEXT_DETECTION
    console.log('▶️  Running DOCUMENT_TEXT_DETECTION on Google Vision…');

    const request = {
      image: { source: { imageUri: imageUrl } },
      features: [{ type: 'DOCUMENT_TEXT_DETECTION' }],
      imageContext: {
         languageHints: ['sq']
      }
    };

    const [visionResult] = await client.annotateImage(request);
    const fullTextAnnotation = visionResult.fullTextAnnotation;
    const extractedText = fullTextAnnotation ? fullTextAnnotation.text : '';

    console.log('✅ Extracted text (DOCUMENT_TEXT_DETECTION):', extractedText);

    // 4️⃣ Format to JSON
    console.log('▶️  Formatting text to JSON…');
    // This formatDataToJson call still expects raw text
    const jsonText = await formatDataToJson(extractedText, imageUrl, saleEndDate, storeId);
    console.log('✅ Formatted JSON:', jsonText);

    // 5️⃣ Cleanup
    fs.unlinkSync(imagePath);
    console.log('✅ Deleted temp file');

    // 6️⃣ Respond
    return res.json({ extractedText, jsonText, imageUrl });

  } catch (err) {
    console.error('❌ Error in /extract-text route:', err);
    return res.status(500).json({
      message: 'Failed to extract text from image.',
      error: err.message
    });
  }
});


app.post('/extract-text3333', upload.single('image'), async (req, res) => {
  console.log('🔍 Extracting text from image…');

  const { saleEndDate, storeId } = req.body;
  console.log('Sale End Date:', saleEndDate);
  console.log('Store ID:', storeId);
  console.log('Image file:', req.file);

  try {
    if (!req.file) {
      console.error('❌ No image file provided.');
      return res.status(400).json({ message: 'No image file provided.' });
    }

    const imagePath = req.file.path;
    console.log(`🛣️  Local path: ${imagePath}`);

    console.log('▶️  Uploading to Cloudinary…');
    const uploadedImage = await cloudinary.uploader.upload(imagePath, {
      folder: 'uploads',
      public_id: req.file.originalname.split('.')[0],
      resource_type: 'image',
      overwrite: true,
    });
    const imageUrl = uploadedImage.secure_url;
    console.log('✅ Uploaded URL:', imageUrl);

    // 3️⃣ OCR with Google Vision
    console.log('▶️  Running textDetection on Google Vision…');
    const [visionResult] = await client.textDetection(imageUrl);
    const detections = visionResult.textAnnotations;
    const extractedText = detections?.[0]?.description || '';
    console.log('✅ Extracted text:', extractedText);

    // 4️⃣ Format to JSON
    console.log('▶️  Formatting text to JSON…');
     // This formatDataToJson call still expects raw text
    const jsonText = await formatDataToJson(extractedText, imageUrl, saleEndDate, storeId);
    console.log('✅ Formatted JSON:', jsonText);

    // 5️⃣ Cleanup
    fs.unlinkSync(imagePath);
    console.log('✅ Deleted temp file');

    // 6️⃣ Respond
    return res.json({ extractedText, jsonText, imageUrl });

  } catch (err) {
    console.error('❌ Error in /extract-text route:', err);
    return res.status(500).json({
      message: 'Failed to extract text from image.',
      error: err.message
    });
  }
});


app.post('/extract-text2', upload.single('image'), async (req, res) => {
  console.log('🔍 Extracting text from image...');

  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No image file provided.' });
    }

    const imagePath = req.file.path;

    // Upload image to Cloudinary
    const uploadedImage = await cloudinary.uploader.upload(imagePath, {
      folder: 'uploads',
      public_id: req.file.originalname.split('.')[0],
      resource_type: 'image',
      overwrite: true,
    });
    console.log('✅ Image uploaded to Cloudinary:', uploadedImage.secure_url);

    // Send image to Google Vision API
    const [result] = await client.textDetection(uploadedImage.secure_url);
    const detections = result.textAnnotations;
    let extractedText = '';

    if (detections && detections.length > 0) {
      extractedText = detections[0].description;
    }

    console.log('🔍 Extracted text:', extractedText);

     // This formatDataToJson call still expects raw text
    const jsonText = await formatDataToJson(extractedText, uploadedImage.secure_url);

    console.log('🔍 Formated json data:', jsonText);

    // Delete temporary uploaded file from server
    fs.unlinkSync(imagePath);

    res.json({
      extractedText: extractedText,
      jsonText: jsonText,
      imageUrl: uploadedImage.secure_url
    });

  } catch (error) {
    console.error('❌ Error extracting text:', error);
    res.status(500).json({ message: 'Failed to extract text from the image.' });
  }
});


async function listAllMediaFiles() {
  try {
    const result = await cloudinary.api.resources({
      type: 'upload',
      max_results: 100,
    });

    const mediaFiles = result.resources.map((resource) => ({
      public_id: resource.public_id,
      format: resource.format,
      secure_url: resource.secure_url,
      thumbnail_url: cloudinary.url(resource.public_id, {
        width: 100,
        height: 100,
        crop: 'thumb',
      }),
    }));
    return mediaFiles;
  } catch (error) {
    console.error('Error fetching media files:', error);
    return { error: 'Error fetching media files' };
  }
};

cloudinary.config({
  cloud_name: 'dt7a4yl1x',
  api_key: '443112686625846',
  api_secret: 'e9Hv5bsd2ECD17IQVOZGKuPmOA4',
});


function generateJwtToken(payload, expiresIn = '240h') {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

function authenticateJWT(req, res, next) {
  const token = req.cookies.jwt;
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ message: 'Invalid or expired token' });
  }
}

app.get('/media-library-json', async (req, res) => {
  const mediaJson = await listAllMediaFiles();
  res.json(mediaJson);
});


app.get('/testing', async (req, res) => {
  const mediaJson = "this is testinggggggggggggg"
  console.log('🟢 Media Library endpoint hit');
  res.json(mediaJson);
});

app.get('/initialize', (req, res) => {
  console.log('🟢 Initialize endpoint hit');
  let token = req.cookies.jwt;
  if (!token) {
      console.log('⚠️ No JWT found in cookies. Generating a new token.');
      const userId = Math.random().toString(36).substring(2);
      token = jwt.sign({ userId }, process.env.TOKEN_SECRET, { expiresIn: '7d' });
      console.log('Generated JWT:', token);
      const query = `INSERT INTO users (userToken, jwt) VALUES (?, ?)`;
      db.query(query, [userId, token], (err) => {
          if (err) {
              console.error('❌ Error inserting new JWT into database:', err);
              return res.status(500).json({ message: 'Failed to initialize user.' });
          }
          res.cookie('jwt', token, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production',
               maxAge: 24 * 60 * 60 * 1000, // 1 day
          });
          return res.json({ message: 'JWT set for new user', userId });
      });
  } else {
      console.log('✅ JWT found in cookies. Verifying...');
      try {
          const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
          console.log('✅ Token is valid:', decoded);
          return res.json({ message: 'User identified', userId: decoded.userId });
      } catch (err) {
          console.error('❌ Invalid JWT:', err.message);
          res.clearCookie('jwt');
          return res.status(401).json({ error: "Invalid token, please reinitialize." });
      }
  }
});


app.get('/initialize2', (req, res) => {
  console.log('Initialize endpoint hit');
  let token = req.cookies.jwt;
  if (!token) {
    console.log('No JWT found in cookies. Generating a new token.');
    const userId = Math.random().toString(36).substring(2);
    token = jwt.sign({ userId }, process.env.TOKEN_SECRET, { expiresIn: '7d' });
    console.log('Generated JWT:', token);
    const query = `INSERT INTO users (userToken, jwt) VALUES (?, ?)`;
    db.query(query, [userId, token], (err) => {
      if (err) {
        console.error('Error inserting new JWT into database:', err);
        return res.status(500).json({ message: 'Failed to initialize user.' });
      }
      res.cookie('jwt', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });
      return res.json({ message: 'JWT set for new user', userId });
    });
  } else {
    const query = `SELECT * FROM users WHERE jwt = ?`;
    db.query(query, [token], (err, results) => {
      if (err) {
        console.error('Error querying JWT from database:', err);
        return res.status(500).json({ message: 'Failed to verify user.' });
      }
      if (results.length > 0) {
        console.log('JWT found in database. Reusing token.');
        const { userToken } = jwt.verify(token, SECRET_KEY);
        const userId = results[0].userId;
        return res.json({ message: 'User identified', userId, userToken });
      } else {
        console.log('JWT not found in database. Treating as a new user.');
        const userId = Math.random().toString(36).substring(2);
        token = generateJwtToken({ userId });
        const insertQuery = `INSERT INTO users (userId, jwt) VALUES (?, ?)`;
        db.query(insertQuery, [userId, token], (err) => {
          if (err) {
            console.error('Error inserting new JWT into database:', err);
            return res.status(500).json({ message: 'Failed to initialize user.' });
          }
          res.cookie('jwt', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          });
          return res.json({ message: 'JWT set for new user', userId });
        });
      }
    });
  }
});


app.post('/save-preferences', authenticateJWT, (req, res) => {
  const { userId } = req.user;
  const { preferences } = req.body;
  res.json({ message: 'Preferences saved', userId, preferences });
});

app.get('/get-preferences', authenticateJWT, (req, res) => {
  const { userId } = req.user;
  res.json({ message: 'Preferences retrieved', userId});
});


app.delete('/deleteProduct/:productId', async (req, res) => {
  console.log('Delete product endpoint hit');
  const productId = req.params.productId;
  console.log('productId received:', productId);
  const dbQuery = (query, params) => {
    return new Promise((resolve, reject) => {
      db.query(query, params, (err, result) => {
        if (err) {
          return reject(err);
        }
        resolve(result);
      });
    });
  };

  try {
    await dbQuery('START TRANSACTION');
    await dbQuery('DELETE FROM productkeywords WHERE productId = ?', [productId]);
    await dbQuery(`
      DELETE FROM keywords
      WHERE keywordId NOT IN (SELECT keywordId FROM productkeywords)
    `);
    await dbQuery('DELETE FROM products WHERE productId = ?', [productId]);
    await dbQuery('COMMIT');
    res.status(200).json({ message: 'Product and related data deleted successfully.' });
  } catch (error) {
    await dbQuery('ROLLBACK');
    console.error('Error deleting product:', error);
    res.status(500).json({ message: 'An error occurred while deleting the product.' });
  }
});

app.post('/insertProducts', (req, res) => {
  const products = req.body;
  if (Array.isArray(products)) {
    products.forEach(product => {
      console.log('Product Description:', product.product_description);
      console.log('Old Price:', product.old_price);
      console.log('New Price:', product.new_price);
      console.log('Discount Percentage:', product.discount_percentage);
      console.log('Sale End Date:', product.sale_end_date);
      console.log('Store ID:', product.storeId);
      console.log('Keywords:', product.keywords.join(', '));
      console.log('---');
    });
    res.status(200).json({ message: 'Products processed successfully' });
  } else {
    res.status(400).json({ message: 'Invalid data format. Expected an array of products.' });
  }
});


async function insertProducts1(jsonData) {
  console.log('Insert products endpoint hit');
  console.log('JSON data received:', jsonData);
  console.log('JSON data type:', typeof jsonData);

  // Check if jsonData is already an object or array
  const products = Array.isArray(jsonData) ? jsonData : JSON5.parse(jsonData);
  console.log('Products received:', products);

  if (!Array.isArray(products)) {
    console.error('Invalid JSON format:', products);
    return; // Return without sending response as this is called from formatDataToJson
  }

  const dbQuery = (query, params) => {
    return new Promise((resolve, reject) => {
      db.query(query, params, (err, result) => {
        if (err) {
          return reject(err);
        }
        resolve(result);
      });
    });
  };

  try {
    await dbQuery('START TRANSACTION');
    for (const product of products) {
      const { product_description, old_price, new_price, discount_percentage, sale_end_date, storeId, keywords, image_url } = product;
      console.log('Processing product:', product_description);

      const productResult = await dbQuery(
        `INSERT INTO products (product_description, old_price, new_price, discount_percentage, sale_end_date, storeId, image_url)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [product_description, old_price, new_price, discount_percentage, sale_end_date, storeId, image_url]
      );

      const productId = productResult.insertId;
      console.log('Inserted productId:', productId);

      if (!Array.isArray(keywords)) {
        console.log('Keywords is not an array:', keywords);
        throw new Error('Keywords must be an array');
      }

      for (const keyword of keywords) {
        console.log('Processing keyword:', keyword);
        const existingKeyword = await dbQuery(
          `SELECT keywordId FROM keywords WHERE keyword = ?`,
          [keyword]
        );

        let keywordId;
        if (existingKeyword.length > 0) {
          keywordId = existingKeyword[0].keywordId;
        } else {
          const newKeywordResult = await dbQuery(
            `INSERT INTO keywords (keyword) VALUES (?)`,
            [keyword]
          );
          keywordId = newKeywordResult.insertId;
        }

        await dbQuery(
          `INSERT INTO productkeywords (productId, keywordId) VALUES (?, ?)`,
          [productId, keywordId]
        );
      }
    }
    await dbQuery('COMMIT');
    console.log('All products and keywords inserted successfully!');
  } catch (err) {
    console.error('Error during product insertion:', err);
    await dbQuery('ROLLBACK');
    console.error('Transaction rolled back due to error:', err);
    throw err;
  }
};


// **UPDATED** formatDataToJson function to work with image URL
async function formatDataToJson(imageUrl, originalImageUrl, saleEndDate, storeId, userId) { // Accepts imageUrl as data source
  console.log('🔍 Formatting data into JSON using Gemini 1.5 Pro from image URL...');
  console.log('Metadata received: Image URL:', originalImageUrl, 'Sale End Date:', saleEndDate, 'Store ID:', storeId, 'User ID:', userId);

  const geminiPrompt = `You are an AI assistant that specializes in extracting structured product sale information from an image of an Albanian retail flyer.

Your task is to analyze the image, identify distinct product entries, and extract the product description, original price (if present), sale price, and discount percentage for each. A product entry typically consists of a product description and one or two prices. Original prices are usually higher and may be positioned near the sale price.

Analyze the visual layout and text content within the image to determine which elements belong to which product. Look for price patterns (numbers with currency symbols), percentage signs, and descriptive text.

For each distinct product entry you identify in the image, create a JSON object in your output array with these exact keys and data types:

* \`product_description\` (string): The complete descriptive text associated with the product in the flyer. Include any size/volume information (e.g., 0,33L, 400ml, 3kg) if it's part of the product's description text in the flyer.
* \`old_price\` (string or null): The text of the original price (if a higher price is present). Remove currency symbols (€). If no distinct original price is found for a product, use \`null\`.
* \`new_price\` (string or null): The text of the current sale price (the lower price). Remove currency symbols (€). If no sale price is found, use \`null\`.
* \`discount_percentage\` (string or null): The numerical value of the discount percentage shown (e.g., "14"). Remove the percentage symbol (%). If no discount percentage is found, use \`null\`.
* \`sale_end_date\` (string): Use the provided value: "${saleEndDate}". Format as "YYYY-MM-DD".
* \`storeId\` (number): Use the provided value: ${storeId}.
* \`userId\` (number): Use the provided value: ${userId}.
* \`image_url\` (string): Use the provided value: "${originalImageUrl}".

Also, generate a list of relevant keywords for each product description. These keywords should be in lowercase, in Albanian, and exclude common articles, conjunctions, prepositions, and size/volume information (like 'kg', 'l', 'pako', numbers, units). Only include words longer than 2 characters. Convert the Albanian letter 'ë' to 'e' for all keywords. The \`keywords\` field should be an array of strings. Limit the keywords to the most relevant 5 per product.

If you can find a date mentioned explicitly in the flyer image that seems to indicate the sale end date, use that date instead of the provided \`${saleEndDate}\`, formatted as "YYYY-MM-DD". If multiple dates are present, use the latest one as the \`sale_end_date\` for all products extracted from this image.

Provide ONLY the JSON array of extracted product objects in your response. Do not include any introductory or concluding text, explanations, or code block markers. Ensure the output is valid JSON.

`;

  try {
    // Correctly structure the content for generateContent
    const response = await generativeModel.generateContent({
      contents: [
        {
          role: 'user', // Added the user role
          parts: [
            { text: geminiPrompt }, // Text part
            {
              fileData: {
                mimeType: 'image/jpeg', // Or image/png, etc. based on your uploaded file type
                fileUri: imageUrl, // Pass the Cloudinary URL here
              },
            }, // File data part
          ],
        },
      ],
    });


    let text = response.response.candidates[0].content.parts[0].text;

    console.log('Raw Gemini Output:', text);

    // Clean up potential markdown code block and backticks
    text = text.replace(/^```json\s*/, '').replace(/\s*```$/, '').replace(/`/g, '');

    try {
        const products = JSON5.parse(text);
        console.log('Parsed JSON:', products);

        // Call the insertion function with the parsed products array
        await insertProducts1(products);

        return products; // Return the formatted JSON data

    } catch (parseError) {
        console.error('JSON Parsing Error:', parseError);
        console.error('Failed JSON Text:', text);
        return null;
    }

  } catch (error) {
      console.error('Gemini API Error:', error);
      // Check for specific error details if available
      if (error.details) {
          console.error('Gemini API Error Details:', error.details);
      }
      if (error.message && error.message.includes("400 Bad Request")) {
           console.error("Possible issue: Incorrect file type or URL for Gemini Vision input.");
      }
      return null;
  }
}


app.put('/rename-image', async (req, res) => {
  const { public_id, new_name } = req.body;
  if (!public_id || !new_name) {
    return res.status(400).json({ error: 'Missing public_id or new_name' });
  }
  try {
    const result = await cloudinary.uploader.rename(public_id, new_name);
    if (result.result === 'ok') {
      res.status(200).json({ message: 'Image renamed successfully' });
    } else {
      res.status(500).json({ error: 'Failed to rename image' });
    }
  }
  catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get('/test', async (req, res) => {
  res.status(200).json({ message: 'Testing successfully....' });
});


app.get("/getStores", (req, res) => {
  const q = `SELECT * from stores order by storeId asc`;
  const userId= req.query.userId;
    db.query(q, (err, data) => {
    if (err) {
      console.log("getStores error:", err);
      return res.json(err);
    }
    return res.json(data);
  });
});


app.get("/isFavorite", (req, res) => {
  const { userId, productId } = req.query;
  const q = `SELECT * FROM favorites WHERE userId = ? AND productId = ?`;
  db.query(q, [userId, productId], (err, result) => {
    if (err) {
      console.error('Error checking favorite:', err);
      return res.status(500).json({ error: 'Failed to check favorite' });
    }
    const isFavorite = result.length > 0;
    res.status(200).json({ isFavorite });
  });
});


app.post("/addFavorite", (req, res) => {
  console.log('Add favorite endpoint hit');
  console.log('Request body:', req.body);
  const { userId, productId } = req.body;
  const q = `INSERT INTO favorites (userId, productId) VALUES (?, ?)`;
  db.query(q, [userId, productId], (err, result) => {
    if (err) {
      console.error('Error adding favorite:', err);
      return res.status(500).json({ error: 'Failed to add favorite' });
    }
    res.status(200).json({ message: 'Favorite added successfully' });
  });
});

app.delete("/removeFavorite", (req, res) => {
  const { userId, productId } = req.body;
  const q = `DELETE FROM favorites WHERE userId = ? AND productId = ?`;
  db.query(q, [userId, productId], (err, result) => {
    if (err) {
      console.error('Error removing favorite:', err);
      return res.status(500).json({ error: 'Failed to remove favorite' });
    }
    res.status(200).json({ message: 'Favorite removed successfully' });
  });
});


app.get("/getUsers", (req, res) => {
  const q = `SELECT * from users order by userId asc`;
  const userId= req.query.userId;
    db.query(q, (err, data) => {
    if (err) {
      console.log("getStores error:", err);
      return res.json(err);
    }
    return res.json(data);
  });
});

app.get("/searchProducts", (req, res) => {
  const { keyword } = req.query;
  let q = `
    SELECT
      p.productId as productId,
      p.product_description as product_description,
      p.old_price as old_price,
      p.new_price as new_price,
      p.discount_percentage as discount_percentage,
      p.sale_end_date as sale_end_date,
      p.storeId as storeId,
      p.image_url as image_url,
      GROUP_CONCAT(k.keyword) AS keywords
    FROM
      products p
    LEFT JOIN
      productkeywords pk ON p.productId = pk.productId
    LEFT JOIN
      keywords k ON pk.keywordId = k.keywordId
  `;
  const queryParams = [];
  if (keyword) {
    const keywords = keyword.split(' ').map(kw => kw.trim());
    const keywordConditions = keywords
      .filter(kw => kw.length > 1)
      .map(() => `k.keyword LIKE ?`)
      .join(' OR ');
    q += ` WHERE ${keywordConditions}`;
    queryParams.push(...keywords.map(kw => `%${kw}%`));
  }
  q += `
    GROUP BY
      p.productId
  `;
  db.query(q, queryParams, (err, results) => {
    if (err) {
      console.error('Error searching products:', err);
      return res.status(500).json({ error: 'Failed to search products' });
    }
    res.status(200).json(results);
  });
});

app.post("/addKeyword", (req, res) => {
  const { productId, keyword } = req.body;
  const q = `INSERT INTO keywords (keyword) VALUES (?) ON DUPLICATE KEY UPDATE keywordId = LAST_INSERT_ID(keywordId)`;
  db.query(q, [keyword], (err, result) => {
    if (err) {
      console.error('Error adding keyword:', err);
      return res.status(500).json({ error: 'Failed to add keyword' });
    }
    const keywordId = result.insertId;
    db.query(
      `INSERT INTO productkeywords (productId, keywordId) VALUES (?, ?)`,
      [productId, keywordId],
      (err, result) => {
        if (err) {
          console.error('Error adding keyword to product:', err);
          return res.status(500).json({ error: 'Failed to add keyword to product' });
        }
        res.status(200).json({ message: 'Keyword added successfully' });
      }
    );
  });
});

app.delete("/removeKeyword", (req, res) => {
  console.log('Remove keyword endpoint hit');
  console.log('Request body:', req.body);
  const { productId, keyword } = req.body;
  db.query(
    `SELECT keywordId FROM keywords WHERE keyword = ?`,
    [keyword],
    (err, result) => {
      if (err) {
        console.error('Error getting keywordId:', err);
        return res.status(500).json({ error: 'Failed to get keywordId' });
      }
      const keywordId = result[0]?.keywordId;
      db.query(
        `DELETE FROM productkeywords WHERE productId = ? AND keywordId = ?`,
        [productId, keywordId],
        (err, result) => {
          if (err) {
            console.error('Error removing keyword from product:', err);
            return res.status(500).json({ error: 'Failed to remove keyword from product' });
          }
          res.status(200).json({ message: 'Keyword removed successfully' });
        }
      );
    }
  );
});


app.put("/updateProductPrices", (req, res) => {
  const { productId, oldPrice, newPrice } = req.body;
  const q = `UPDATE products SET old_price = ?, new_price = ? WHERE productId = ?`;
  db.query(q, [oldPrice, newPrice, productId], (err, result) => {
    if (err) {
      console.error('Error updating product prices:', err);
      return res.status(500).json({ error: 'Failed to update product prices' });
    }
    res.status(200).json({ message: 'Product prices updated successfully' });
  });
});


app.put("/editProductDescription", (req, res) => {
  const { productId, newDescription } = req.body;
  const q = `UPDATE products SET product_description = ? WHERE productId = ?`;
  db.query(q, [newDescription, productId], (err, result) => {
    if (err) {
      console.error('Error updating product description:', err);
      return res.status(500).json({ error: 'Failed to update product description' });
    }
    res.status(200).json({ message: 'Product description updated successfully' });
  });
});

app.put("/editProductSaleDate", (req, res) => {
  const { productId, sale_end_date } = req.body;
  console.log('Received sale_end_date:', sale_end_date);
  const date = new Date(sale_end_date);
  const formattedDate = date.toISOString().slice(0, 19).replace('T', ' ');
  console.log('Formatted date:', formattedDate);
  const q = `UPDATE products SET sale_end_date = ? WHERE productId = ?`;
  db.query(q, [formattedDate, productId], (err, result) => {
    if (err) {
      console.error('Error updating product description:', err);
      return res.status(500).json({ error: 'Failed to update product date' });
    }
    res.status(200).json({ message: 'Product date updated successfully' });
  });
});


app.put("/editStore", (req, res) => {
  const { productId, storeId } = req.body;
  const q = `UPDATE products SET storeId = ? WHERE productId = ?`;
  db.query(q, [storeId, productId], (err, result) => {
    if (err) {
      console.error('Error updating store :', err);
      return res.status(500).json({ error: 'Failed to update store' });
    }
    res.status(200).json({ message: 'Store updated successfully' });
  });
});

app.get("/getProducts", async (req, res) => {
  console.log('getProducts endpoint hit');
  const userId = parseInt(req.query.userId, 10) || null;
  let storeId = parseInt(req.query.storeId, 10);
  const isFavorite = req.query.isFavorite || null;
  const onSale = req.query.onSale || null;
  const keyword = req.query.keyword || null;
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 20) || 20;
  const offset = (page - 1) * limit;
  const today = new Date().toISOString().split('T')[0];

  if (isNaN(storeId) || storeId <= 0) {
    storeId = null;
  }

  let q = `
    SELECT
      p.productId,
      p.product_description,
      p.old_price,
      p.new_price,
      p.discount_percentage,
      p.sale_end_date,
      p.storeId,
      p.image_url,
      s.storeName,
      GROUP_CONCAT(k.keyword) AS keywords,
      CASE WHEN f.userId IS NOT NULL THEN TRUE ELSE FALSE END AS isFavorite,
      CASE WHEN p.sale_end_date >= ? THEN TRUE ELSE FALSE END AS productOnSale,
      (
        SELECT COUNT(*)
        FROM productkeywords pkf
        JOIN keywords kf ON pkf.keywordId = kf.keywordId
        WHERE pkf.productId = p.productId
          AND kf.keyword IN (
            SELECT k.keyword
            FROM favorites f
            JOIN productkeywords pk ON f.productId = pk.productId
            JOIN keywords k ON pk.keywordId = k.keywordId
            WHERE f.userId = ?
          )
      ) AS keywordMatchCount
    FROM
      products p
    LEFT JOIN
      productkeywords pk ON p.productId = pk.productId
    LEFT JOIN
      keywords k ON pk.keywordId = k.keywordId
    LEFT JOIN
      favorites f ON p.productId = f.productId AND f.userId = ?
    LEFT JOIN
      stores s ON p.storeId = s.storeId
  `;

  const params = [today, userId, userId];
  let conditions = [];
  if (storeId !== null) {
    conditions.push(`p.storeId = ?`);
    params.push(storeId);
  }

  if (isFavorite && isFavorite.trim() === 'true') {
    console.log('isFavorite condition hit');
    conditions.push(`f.userId = ?`);
    params.push(userId);
  }

  if (onSale === 'true') {
    conditions.push(`p.sale_end_date >= ?`);
    params.push(today);
  }

  if (keyword) {
    const keywords = keyword.split(' ').map(kw => kw.trim());
    const keywordConditions = keywords
      .filter(kw => kw.length > 1)
      .map(() => `k.keyword LIKE ?`)
      .join(' OR ');
    if (keywordConditions.length > 0) {
      conditions.push(`(${keywordConditions})`);
      params.push(...keywords.filter(kw => kw.length > 1).map(kw => `${kw}%`));
    }
  }

  if (conditions.length > 0) {
    q += ' WHERE ' + conditions.join(' AND ');
  }

  q += `
    GROUP BY
      p.productId
    ORDER BY
      p.productId DESC,
      productOnSale DESC,
      isFavorite DESC,
      keywordMatchCount DESC
    LIMIT ? OFFSET ?
  `;
  params.push(limit, offset);

  db.query(q, params, (err, data) => {
    if (err) {
      console.log("getProducts error:", err);
      return res.json(err);
    }
    const nextPage = data.length === limit ? page + 1 : null;
    return res.json({ data, nextPage });
  });
});


app.get("/getProductsDashboard", async (req, res) => {
  const userId = parseInt(req.query.userId, 10) || null;
  let storeId = parseInt(req.query.storeId, 10);
  const isFavorite = req.query.isFavorite || null;
  const onSale = req.query.onSale || null;
  const keyword = req.query.keyword || null;
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const offset = (page - 1) * limit;
  const today = new Date().toISOString().split('T')[0];

  if (isNaN(storeId) || storeId <= 0) {
    storeId = null;
  }

  let q = `
    SELECT
      p.productId,
      p.product_description,
      p.old_price,
      p.new_price,
      p.discount_percentage,
      p.sale_end_date,
      p.storeId,
      p.image_url,
      s.storeName,
      GROUP_CONCAT(k.keyword) AS keywords,
      CASE WHEN f.userId IS NOT NULL THEN TRUE ELSE FALSE END AS isFavorite,
      CASE WHEN p.sale_end_date >= ? THEN TRUE ELSE FALSE END AS productOnSale,
      (
        SELECT COUNT(*)
        FROM productkeywords pkf
        JOIN keywords kf ON pkf.keywordId = kf.keywordId
        WHERE pkf.productId = p.productId
          AND kf.keyword IN (
            SELECT k.keyword
            FROM favorites f
            JOIN productkeywords pk ON f.productId = pk.productId
            JOIN keywords k ON pk.keywordId = k.keywordId
            WHERE f.userId = ?
          )
      ) AS keywordMatchCount
    FROM
      products p
    LEFT JOIN
      productkeywords pk ON p.productId = pk.productId
    LEFT JOIN
      keywords k ON pk.keywordId = k.keywordId
    LEFT JOIN
      favorites f ON p.productId = f.productId AND f.userId = ?
    LEFT JOIN
      stores s ON p.storeId = s.storeId
  `;

  const params = [today, userId, userId];
  let conditions = [];
  if (storeId !== null) {
    conditions.push(`p.storeId = ?`);
    params.push(storeId);
  }

  if (isFavorite && isFavorite.trim() === 'true') {
    console.log('isFavorite condition hit');
    conditions.push(`f.userId = ?`);
    params.push(userId);
  }

  if (onSale === 'true') {
    conditions.push(`p.sale_end_date >= ?`);
    params.push(today);
  }

  if (keyword) {
    const keywords = keyword.split(' ').map(kw => kw.trim());
    const keywordConditions = keywords
      .filter(kw => kw.length > 1)
      .map(() => `k.keyword LIKE ?`)
      .join(' OR ');
    if (keywordConditions.length > 0) {
      conditions.push(`(${keywordConditions})`);
      params.push(...keywords.map(kw => `%${kw}%`));
    }
  }

  if (conditions.length > 0) {
    q += ' WHERE ' + conditions.join(' AND ');
  }

  q += `
    GROUP BY
      p.productId
    ORDER BY
      p.productId DESC,
      productOnSale DESC,
      isFavorite DESC,
      keywordMatchCount DESC
    LIMIT ? OFFSET ?
  `;
  params.push(limit, offset);

  db.query(q, params, (err, data) => {
    if (err) {
      console.log("getProducts error:", err);
      return res.json(err);
    }
    const nextPage = data.length === limit ? page + 1 : null;
    return res.json({ data, nextPage });
  });
});


app.delete('/delete-image', async (req, res) => {
    const { public_id } = req.body;
    if (!public_id) {
      return res.status(400).json({ error: 'Missing public_id' });
    }
    try {
      const result = await cloudinary.uploader.destroy(public_id);
      if (result.result === 'ok') {
        res.status(200).json({ message: 'Image deleted successfully' });
      } else {
        res.status(500).json({ error: 'Failed to delete image' });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });


app.get('/chatgptExtractProducts', async (req, res) => {
  const { storeId, imageUrl } = req.query;
  const imageBaseUrl = "https://res.cloudinary.com/dt7a4yl1x/image/upload/";
  const imageName = imageUrl.split('/').pop();
  console.log('storeId:', storeId);
  console.log('imageUrl:', imageUrl);
  console.log('imageName:', imageName);

  const prompt = `Can you extract product sale information in albanian language from this sales flyer for each product in the image , if available.
  Convert ë letter to e for all the keywords. Do not include conjunctions, articles words in albanian, in keywords.
  Do not include size info for keywords and only words with more than 2 characters as keywords.
  The storeId is:${storeId}.
 populate the "image_url" field with a variable ${imageName} from above".
 If some data is not available, leave the field empty.
  The response should be in the JSON format,  like the following example:
  [
    {
      "product_description": "Mandarina kg",
      "old_price": 0.89,
      "new_price": 0.69,
      "discount_percentage": 22,
      "sale_end_date": "2024-12-26",
      "storeId": 1,
      "image_url": ${imageName},
      "keywords": ["mandarina"]
    },
    {
      "product_description": "Kerpudhe pako",
      "old_price": 1.49,
      "new_price": 0.99,
      "discount_percentage": 33,
      "sale_end_date": "2024-12-26",
      "storeId": 1,
      "image_url": ${imageName},
      "keywords": ["kerpudhe"]
}]

` ;

  const response = await openai.chat.completions.create({
    model: "gpt-4-turbo",
    messages: [
      {
        role: "user",
        content: [
          { type: "text", text: prompt },
          {
            type: "image_url",
            image_url: {
              "url": imageUrl,
            },
          },
        ],
      },
    ],
  });

  let resp = response.choices[0];
  let content = resp.message.content;
  content = content.replace(/```json\n/, '').replace(/```$/, '');
  const productList = JSON.parse(content);
  console.log(productList);
  res.json(productList);
});


app.post('/upload-multiple', upload.array('images', 10), async (req, res) => {
  const { folderName, storeId } = req.body;
  console.log('folderName:', folderName);
  console.log('storeId:', storeId);
  try {
    const uploadPromises = req.files.map(async (file) => {
      const imagePath = file.path;
      const result = await cloudinary.uploader.upload(imagePath, {
        folder: folderName || 'default-folder',
        use_filename: true,
        unique_filename: false,
      });
      console.log('result from upload:', result.public_id);
      const publicId = result.public_id;
      const imageName = publicId.split('/').pop();
      const transformationResult = await cloudinary.uploader.upload(publicId, {
        type: 'upload',
        overwrite: true,
        transformation: [
          {
            overlay: {
              font_family: 'Arial',
              font_size: 30,
              padding: 10,
              text: '#' + imageName + ' ' + '@' + storeId,
            },
            gravity: 'north',
            y: -30,
            x: 10
          }
        ],
      });
      console.log('Transformed image URL:', transformationResult.secure_url);
      const options = {
        url: transformationResult.secure_url,
        dest: '../../downloads/',
      };
      download.image(options)
        .then(({ filename }) => {
          console.log('Saved to', filename);
        })
        .catch((err) => console.error(err));
      fs.unlinkSync(imagePath);
      return { success: true, url: result.secure_url, public_id: result.public_id, format: result.format };
    });
    const results = await Promise.all(uploadPromises);
    res.json(results);
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to upload image' });
  }
});


app.post('/upload', upload.array('images', 10), async (req, res) => {
  try {
    const uploadPromises = req.files.map(async (file) => {
      const imagePath = file.path;
      const { folderName } = req.body;
      console.log('folderName:', folderName);
      const result = await cloudinary.uploader.upload(imagePath, {
        folder: folderName || 'default-folder',
        use_filename: true,
        unique_filename: false,
      });
      console.log('result from upload:', result.public_id);
      const publicId = result.public_id;
      const imageName = publicId.split('/').pop();
      const transformationResult = await cloudinary.uploader.upload(result.secure_url, {
        type: 'upload',
        overwrite: true,
        transformation: [
          {
            overlay: {
              font_family: 'Arial',
              font_size: 30,
              padding: 10,
              text: '#' + imageName,
            },
            gravity: 'north',
            y: -30,
            x: 10
          }
        ],
      });
      console.log('Transformed image URL:', transformationResult.secure_url);
      const saveLocally = async (url, destination) => {
        try {
          const opts = { url, dest: destination };
          const { filename } = await download.image(opts);
          console.log('Saved to locally:', filename);
        } catch (error) {
          console.error(error);
        }
      };
      const transformedImageUrl = transformationResult.secure_url;
      const localDestination = '../../Downloads/';
      await saveLocally(transformedImageUrl, localDestination);
      fs.unlinkSync(imagePath);
      return {
        success: true,
        url: result.secure_url,
        public_id: result.public_id,
        format: result.format
      };
    });
    const images = await Promise.all(uploadPromises);
    res.json({ success: true, images });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Failed to upload image' });
  }
});


const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
