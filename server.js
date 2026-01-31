import multer from 'multer';
import cloudinary from './cloudinaryConfig.js';
import cors from 'cors';
import fs from 'fs';
import dotenv from 'dotenv';
import { sendDailyProductNotifications } from './notificationScheduler.js';
import os from 'os'; // <-- FIX: Import the 'os' module



// --- START: CRITICAL CREDENTIALS DEBUGGING ---
// This block will help us verify if the server can find and read your credentials file.
try {
  const credentialsPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (!credentialsPath) {
    console.error('❌ FATAL: GOOGLE_APPLICATION_CREDENTIALS environment variable is NOT SET.');
  } else {
    console.log(`✅ GOOGLE_APPLICATION_CREDENTIALS is set to: ${credentialsPath}`);
    if (fs.existsSync(credentialsPath)) {
      console.log('✅ Credentials file exists at the specified path.');
      const fileContent = fs.readFileSync(credentialsPath, 'utf8');
      const credentials = JSON.parse(fileContent);
      if (credentials.private_key && credentials.client_email) {
        console.log('✅ Credentials file was read and parsed successfully. It contains the required keys.');
      } else {
        console.error('❌ FATAL: Credentials file is missing required keys like "private_key" or "client_email".');
      }
    } else {
      console.error(`❌ FATAL: Credentials file NOT FOUND at path: ${credentialsPath}`);
    }
  }
} catch (e) {
  console.error('❌ FATAL: An error occurred during credential verification:', e);
}

// We no longer need groupTextElementsSpatially if extracting directly from image
// import { groupTextElementsSpatially } from './utils.js';

import identifyUserMiddleware from './identifyUserMiddleware.js'
import  {queryPromise}  from './dbUtils.js';
import { uploadFacebookPhotoToCloudinary } from './uploadFacebookPhoto.js';

import { fetchFacebookPosts } from './rapidApi.js';

import { Expo } from 'expo-server-sdk'; // 1. IMPORT THE SDK



dotenv.config();

import express from 'express';

import { fileURLToPath } from "url";
import path from "path";

// We no longer need the Google Vision client if extracting directly from image
// import vision from '@google-cloud/vision';

import JSON5 from 'json5';

const allMessages = [];



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

const vertexAI = new VertexAI({
  project: 'vision-ai-455010', 
  location: 'europe-west3',
  keyFilename: keyFilePath, // Path to your service account key file

}); // Replace with your project and location

console.log('✅ VertexAI client initialized in server.js');


// Load private key for Apple authentication (keeping this as it seems unrelated to image extraction)
const privateKeyPath = path.join(__dirname, "./persistent/keys/AuthKey_6YK9NFRYH9.p8"); // Path to your .p8 key file
const privateKey = fs.readFileSync(privateKeyPath, "utf8");

// We no longer need the Google Vision client instance
// const client = new vision.ImageAnnotatorClient({
//   keyFilename: path.join(__dirname, './persistent/keys/vision-ai-455010-6d2a9944437b.json'), // Replace with your key file path
// });


import { ApifyClient } from 'apify-client';


// Initialize Apify client with your token
const apify = new ApifyClient({
  token: process.env.APIFY_TOKEN  // Replace with your Apify API token
});


console.log('✅ Apify client initialized in server.js', process.env.APIFY_TOKEN );

import { format } from 'path';
import db from './connection.js';


import cookieParser from 'cookie-parser';
import bodyParser from'body-parser';

import AppleSigninAuth from 'apple-signin-auth';



import download, { image } from 'image-downloader';

export const app = express();


import jwt from 'jsonwebtoken';

import webPush from 'web-push';

import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as AppleStrategy } from 'passport-apple';

import session from 'express-session';
import axios, { all } from "axios";

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


//




// Apple Sign-In Route (keeping these as they are authentication related)




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
        const insertQuery = `INSERT INTO users (first_name, email) VALUES (?, ?)`;
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



// Specify the model you want to use (e.g., Gemini 1.5 Pro)
//const model = 'gemini-2.5-pro'; // Updated to Gemini 2.5 Pro

const model = 'gemini-1.5-flash-002';

// Access the generative model
const generativeModel = vertexAI.getGenerativeModel({
    model: model,
    generation_config: {
        temperature: 0.1,
        topP: 0.8,
        topK: 40,
        maxOutputTokens: 4096 // Increased max output tokens for potentially larger JSON
    },
});



// Apple Callback Route (keeping this)
const corsOptions = {
  origin: [process.env.FRONTEND_URL, process.env.FRONTEND_URL2,
    'http://localhost:5173',
    'http://192.168.1.2:5173', // Allow local network IPs
    'http://192.168.1.5:3000', // Add your server's local IP
    // how to  allow local network IPs in CORS?
    'http://192.168.1.x', // Allow all local network IPs
    'http://localhost:3000', // Allow local development
    'http://localhost:8081', // Allow local development
    'http://localhost:8080', // Allow local development
    'http://192.168.1.5:8081', 
    'https://www.meniven.com',
    'https://qg048c0c0wos4o40gos4k0kc.128.140.43.244.sslip.io',
    'https://singular-catfish-deciding.ngrok-free.app',
    // This regex allows any IP on the 192.168.1.x subnet with any port
    /^http:\/\/192\.168\.1\.\d{1,3}(:\d+)?$/ 
  ] , // Replace with your frontend's origin
  credentials: true,
  origin: true,
  sameSite: 'none', 
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

console.log('corsOptions:', corsOptions);

app.use(cors(corsOptions));
app.use(cookieParser());
app.use(bodyParser.json());

app.use(identifyUserMiddleware);




import authRoutes from "./routes/authRoutes.js";
import { time } from 'console';
app.use("/auth", authRoutes);




app.post('/dashboardLogin', (req, res) => {
  const { username, password } = req.body;
  console.log('🔒 Login attempt:', username);
  console.log('🔒 Password:' , password) ;
  const query = 'SELECT * FROM users WHERE first_name = ? AND last_name = ?';
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


app.get('/facebook-photos', async (req, res) => {
  const pageId = req.query.facebookPageId;

  console.log(`🔍 Fetching Facebook photos for page ID: ${pageId}`);

  // insert the log in allMessages array

  allMessages.push(`🔍 Fetching Facebook photos for page ID: ${pageId}`);


  if (!pageId) {
    return res.status(400).json({ error: 'Missing page_id query parameter' });
  }

  const data = await fetchFacebookPosts(pageId);

  // Extract photo objects as array from the results object
  const photoArray = Object.values(data.results || {});

  console.log(`📸 Extracted ${photoArray} photos from page ID: ${pageId}`);

  allMessages.push(`📸 Extracted ${photoArray.length} photos from page ID: ${pageId}`);

  // Return in the format expected by Dashboard.jsx
  res.json({ items: photoArray , allMessages: allMessages });

});


// ...existing code...

app.get('/facebook-posts', async (req, res) => {
  const pageId = req.query.facebookPageId;
  const debugMessages = [];

  debugMessages.push(`🔍 [facebook-posts] Called with facebookPageId: ${pageId}`);
  console.log(`🔍 [facebook-posts] Called with facebookPageId: ${pageId}`);

  if (!pageId) {
    debugMessages.push('❌ [facebook-posts] Missing facebookPageId query parameter');
    console.error('❌ [facebook-posts] Missing facebookPageId query parameter');
    return res.status(400).json({ error: 'Missing facebookPageId query parameter', debugMessages });
  }

  try {
    const posts = await fetchFacebookPosts(pageId);
    debugMessages.push(`✅ [facebook-posts] fetchFacebookPosts returned ${posts.length} posts`);
    console.log(`✅ [facebook-posts] fetchFacebookPosts returned:`, posts);
    debugMessages.push(`✅ [facebook-posts] fetchFacebookPosts returned: ${posts}`);

    // Flatten posts to array of photo objects for frontend compatibility
    const items = [];
    posts.forEach((post, postIdx) => {
      debugMessages.push(`🔎 [facebook-posts] Post #${postIdx + 1}: message="${post.message}", images=${(post.images || []).length}`);
      (post.images || []).forEach((imgObj, imgIdx) => {
        items.push({
          postId: post.postId,
          message: post.message,
          created_time: post.created_time,
          uri: imgObj.uri,
          image: imgObj.uri,
          imageData: post.imageData ,
          imageId: imgObj.id,
          timestamp: post.timestamp // Use post timestamp or current time
        });
        debugMessages.push(`  📸 [facebook-posts] Added image #${imgObj.id} for post #${post.postId}:`);
      });
    });

    debugMessages.push(`📦 [facebook-posts] Flattened to ${items.length} image items`);
    console.log(`📦 [facebook-posts] Flattened to ${items.length} image items`);

    // Return both the flat array and the grouped posts for debugging
    res.json({
      items,
      posts, // grouped by post for debugging
      debugMessages
    });
  } catch (err) {
    debugMessages.push(`❌ [facebook-posts] API error: ${err?.message || err}`);
    console.error('❌ [facebook-posts] API error:', err);
    res.status(500).json({ error: err.message, debugMessages });
  }
});

// ...existing code...

// --- MODIFIED: Manually trigger scheduled notification logic for ALL users ---
// This endpoint now ignores any userId in the body and runs the full notification job.

// --- NEW: Manually trigger scheduled notification logic for a single user ---
app.post('/trigger-user-notifications', async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'User ID is required.' });
  }

  console.log(`[Manual Trigger] Received request for user: ${userId}`);

  try {
    // 1. Get matching on-sale products for the user based on favorite keywords
    const matchingProductsQuery = `
      WITH UserFavoriteKeywords AS (
        SELECT DISTINCT k.keyword
        FROM favorites f
        JOIN productkeywords pk ON f.productId = pk.productId
        JOIN keywords k ON pk.keywordId = k.keywordId
        WHERE f.userId = ?
      ),
      ProductsOnSale AS (
        SELECT p.productId, p.product_description, k.keyword
        FROM products p
        JOIN productkeywords pk ON p.productId = pk.productId
        JOIN keywords k ON pk.keywordId = k.keywordId
        WHERE p.sale_end_date >= CURDATE()
      )
      SELECT DISTINCT pos.productId
      FROM UserFavoriteKeywords ufk
      JOIN ProductsOnSale pos ON ufk.keyword = pos.keyword;
    `;
    const matchingProducts = await queryPromise(matchingProductsQuery, [userId]);

    if (matchingProducts.length === 0) {
      console.log(`[Manual Trigger] No matching on-sale products found for user ${userId}.`);
      return res.status(200).json({ message: 'Nuk u gjetën produkte në ofertë që përputhen me preferencat tuaja.' });
    }

    // 2. Get user's push tokens
    const tokenResults = await queryPromise('SELECT token FROM push_tokens WHERE user_id = ?', [userId]);
    if (tokenResults.length === 0) {
      console.log(`[Manual Trigger] No push tokens found for user ${userId}.`);
      return res.status(404).json({ message: 'Përdoruesi nuk ka shenja njoftimi të regjistruara.' });
    }
    const tokens = tokenResults.map(row => row.token);

    // 3. Construct and send notifications
    const productIds = matchingProducts.map(p => p.productId);
    const productCount = productIds.length;
    const body = `Ju keni ${productCount} produkte në ofertë që përputhen me preferencat tuaja.`;
    
    const messages = [];
    for (const pushToken of tokens) {
      if (!Expo.isExpoPushToken(pushToken)) continue;
      messages.push({
        to: pushToken,
        sound: 'default',
        title: '✨ Oferta të Përshtatura për Ju!',
        body: body,
        data: { screen: 'ProductsOnSale', productIds: productIds },
      });
    }


    if (messages.length === 0) {
        return res.status(400).json({ message: 'Nuk u gjetën shenja të vlefshme njoftimi.' });
    }

    const expo = new Expo({ useFcmV1: true });
    const chunks = expo.chunkPushNotifications(messages);
    
    console.log(`[Manual Trigger] Sending ${messages.length} notification(s) to user ${userId}...`);
    for (let chunk of chunks) {
        await expo.sendPushNotificationsAsync(chunk);
    }
    console.log(`[Manual Trigger] Notifications sent successfully to user ${userId}.`);

    res.status(200).json({ message: `Njoftimi u dërgua me sukses për ${productCount} produkte.` });

  } catch (error) {
    console.error(`[Manual Trigger] Error processing request for user ${userId}:`, error);
    res.status(500).json({ error: 'Gabim në server gjatë dërgimit të njoftimit.' });
  }
});


// --- NEW: Manually trigger the full notification job for all eligible users ---
app.post('/trigger-all-user-notifications', async (req, res) => {
  console.log('[Manual Trigger] Received request to run the full notification job for all users.');
  try {
    // We trigger the function but don't wait for it to finish,
    // allowing the dashboard to get an immediate response.
    sendDailyProductNotifications(true); 
    
    res.status(202).json({ message: 'Procesi i dërgimit të njoftimeve ka filluar. Kontrolloni regjistrat e serverit për detaje.' });
  } catch (error) {
    console.error('[Manual Trigger] Error starting the notification job:', error);
    res.status(500).json({ error: 'Gabim gjatë fillimit të procesit të njoftimeve.' });
  }
});


// ...existing code...
app.get('/products-by-ids', async (req, res) => {
  const { ids } = req.query; // Expecting a comma-separated string of IDs
  const userId = req.identifiedUser ? req.identifiedUser.userId : null;

  if (!ids) {
    return res.status(400).json({ error: 'Product IDs are required.' });
  }

  // Sanitize input by splitting, parsing to int, and filtering out invalid numbers
  const productIds = ids.split(',').map(id => parseInt(id.trim(), 10)).filter(Number.isFinite);

  if (productIds.length === 0) {
    return res.status(400).json({ error: 'No valid product IDs provided.' });
  }

  try {
    // UPDATED: The query now joins with the favorites table to check the favorite status for the current user.
    const query = `
      SELECT 
        p.*,
        f.userId IS NOT NULL AS isFavorite
      FROM 
        products p
      LEFT JOIN 
        favorites f ON p.productId = f.productId AND f.userId = ?
      WHERE 
        p.productId IN (?)
    `;
    const products = await queryPromise(query, [userId, productIds]);
    res.status(200).json(products);
  } catch (error) {
    console.error('Error fetching products by IDs:', error);
    res.status(500).json({ error: 'Failed to fetch products.' });
  }
});


// API endpoint to get Facebook photo URLs for a specific date
// ...existing code...


// API endpoint to get Facebook photo URLs for a specific date
app.post('/get-facebook-photos', async (req, res) => {


 // console.log(`🔍 Fetching Facebook photos for page: ${pageUrl} on date: ${date}`);


  const { selectedStore, facebookUrl } = req.body;

  console.log(`🔍 Fetching Facebook photos for store: ${selectedStore} with URL: ${facebookUrl}`);



  const facebookData = [
    {url: facebookUrl, storeId: selectedStore}
  ]; 

  console.log(`🔍 Facebook data to scrape:`, facebookData);


  console.log(`🔍 Fetching Facebook photos ....`);




  if(facebookData.length === 0) {
    console.error(`❌ No URLs found for storeId ${mystoreId}`);
    return res.status(404).json({ error: `No URLs found for storeId ${mystoreId}` });
  }
  


  try {
    const input = {
      startUrls: facebookData ,
      resultsLimit: 10,
      proxy: {
        useApifyProxy: true,
        apifyProxyGroups: ['RESIDENTIAL'],
      },
    };

    // Run the actor
    const run = await apify.actor('apify/facebook-photos-scraper').call(input);

    // Fetch dataset items
    const { items } = await apify.dataset(run.defaultDatasetId).listItems();


    console.log(`📸 Fetched ${items.length} items from Facebook.`);
    //console.log(`📸 Items:`, items);



    res.json({
      items: items
    });
  } catch (err) {
    console.error('Error:', err.message);
    res.status(500).json({ error: 'Failed to fetch photos', details: err.message });
  }
});



// Consider removing this if /auth/check-session is sufficient and used by frontend
app.get("/check-session", async (req, res) => { // Added async

  console.log("🔍 Checking session...");
  
  if (req.identifiedUser && req.identifiedUser.userId) {
      // User identified by middleware, verify against DB
      try {
          // Fetch necessary details, including registration status/email
          const query = `SELECT id, email, first_name, is_registered FROM users WHERE id = ?`;
          const results = await queryPromise(query, [req.identifiedUser.userId]);

          if (results.length === 0) {
            console.log(`⚠️ User ${req.identifiedUser.userId} not found in DB during check-session.`);
              console.warn(`⚠️ User ${req.identifiedUser.userId} from token not found in DB during check-session. Clearing cookie.`);
              res.clearCookie("jwt");
              return res.json({ isLoggedIn: false, isRegistered: false, userId: null, email: null });
          }

          const user = results[0];

          console.log(`🔍 User found in DB: ${user.id}, Email: ${user.email || "No email"}`)  ;

          console.log(`✅ Session check successful for userId: ${user.id}, Registered: ${user.is_registered}`);
          return res.json({
              isLoggedIn: true, // Means a valid ID exists
              isRegistered: !!user.is_registered, // Check registration status
              userId: user.id,
              email: user.email // Will be null for anonymous users
          });

      } catch (err) {
          console.error("❌ DB error during /check-session:", err);
          return res.status(500).json({ isLoggedIn: false, isRegistered: false, userId: null, email: null });
      }
  } else {
      // No valid token identified by middleware
      console.log("⚠️ No valid token found in /check-session. Clearing cookie.");
      return res.json({ isLoggedIn: false, isRegistered: false, userId: null, email: null });
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


// add api endpoint like /extract-text that calls extractSaleEndDateFromImage and returns the sale end date

app.post('/extract-sale-end-date', async (req, res) => {

  const { photos} = req.body;

  const imageUrls = photos;


  console.log('🔍 Extracting sale end date from image URL:', photos);


try {
    const results = [];
    for (const imageUrl of imageUrls) {
      let sale_end_date = null;
      try {
        sale_end_date = await extractSaleEndDateFromImage(imageUrl);
      } catch (err) {
        console.error('❌ Error extracting date for image:', imageUrl, err);
      }
      results.push({ image: imageUrl, sale_end_date: sale_end_date || null });
    }
    return res.json(results);
  } catch (err) {
    console.error('❌ Error in /extract-sale-end-date route:', err);
    return res.status(500).json({
      message: 'Failed to extract sale end date from images.',
      error: err.message
    });
  }

});


// ...existing code...

/**
 * Enhanced /extract-text-single endpoint:
 * - Accepts: { images: [ { imageUrl, imageId, storeId, flyerBookId, facebookUrl, postText, created_time, ... } ] }
 * - Uploads all images to Cloudinary (skips those already in DB)
 * - Calls formatDataToJson with all uploaded URLs and metadata arrays
 * - Saves each imageId to facebookPhotos table
 * - Returns: uploaded Cloudinary URLs, extracted products, allMessages, and debug info
 */
app.post('/extract-text-single', async (req, res) => {
  console.log('🔍 [extract-text-single] Extracting data from images using Gemini 1.5 Pro…');

  const images = req.body.images;
  if (!Array.isArray(images) || images.length === 0) {
    console.error('❌ No images array provided.');
    return res.status(400).json({ message: 'No images array provided.' });
  }

// check if storeId and userId are provided in the request body

console.log('🔍 [extract-text-single] Received images:', images);
console.log('🔍 [extract-text-single] Store ID:', images[0].storeId);
console.log('🔍 [extract-text-single] Image idss', images[0].imageId) ;

allMessages.push(`🔍 [extract-text-single] Received images: ${JSON.stringify(images)}`);

 
  if (!images[0].storeId) {
    console.error('❌ Missing storeId in request body.');
    return res.status(400).json({ message: 'Missing storeId in request body.' });
  }

  // Debug: log all received images
  images.forEach((img, idx) => {
    console.log(`[extract-text-single] Image #${idx + 1}:`, img);
  });

  // Prepare arrays for new images (not in DB)
  const newImages = [];
  for (const img of images) {
    newImages.push(img);
  }

  if (newImages.length === 0) {
    return res.status(400).json({ message: 'All imageIds already exist in database.' });
  }


  // Upload all new images to Cloudinary
  const { uploadMultipleFacebookPhotosToCloudinary } = await import('./uploadFacebookPhoto.js');

  //const imageUrlsToUpload = images.map(img => img.imageUrl + '&imageId=' + img.imageId );

  // make imageUrlsToUpload an array of objects of image URLs to upload with imageUrl and imageId

  const imageUrlsToUpload = images.map(img => ({
    imageUrl: img.imageUrl,
    imageId: img.imageId,
    
  }));


  let uploadResults = [];
  let cloudinaryUrls = [];


    try {
      uploadResults = await uploadMultipleFacebookPhotosToCloudinary(imageUrlsToUpload);
      cloudinaryUrls = uploadResults.map(img => img.uploadedUrl);
      //imageIds = uploadResults.map(img => img.imageId);
      console.log('✅ Uploaded images to Cloudinary.');
    } catch (err) {
      console.error('❌ Error uploading images to Cloudinary:', err);
      return res.status(500).json({ error: 'Failed to upload images to Cloudinary', details: err.message });
    }

  // print storeId and userId from images 
  console.log('🔍 [extract-text-single] Store ID:', images[0].storeId);

  // Prepare metadata arrays for formatDataToJson
  const storeId  = images[0].storeId; // Assuming storeId is provided in the first image object
  const postId = images[0].postId; // Optional postId, default to null if not provided
  const userId = images[0].userId || 1; // Default to 1 if userId not provided
  const flyerBookId = images[0].flyerBookId // Generate random flyerBookId if not provided
  // Optionally, collect postText and facebookUrl if you want to use them in formatDataToJson
  const postText = newImages.map(img => img.postText || '');
  const imageId = images[0].imageId; 

  const timestamp = images[0].timestamp // Use created_time or current time
  // print potText array

  

  console.log('🔍 [extract-text-single] timestamp', timestamp);



  console.log('🔍 [extract-text-single] Post Text Array:', postText);
  console.log('🔍 [extract-text-single] postId:', postId);
  console.log('🔍 [extract-text-single] photo ID:', storeId);
  //console.log('🔍 [extract-text-single] Image Data Array:', imageId);
  allMessages.push(`🔍 [extract-text-single] Post Text Array: ${JSON.stringify(postText)}`);
  allMessages.push(`🔍 [extract-text-single] postId: ${postId}`);
  allMessages.push(`🔍 [extract-text-single] photo ID: ${storeId}`);
  allMessages.push(`🔍 [extract-text-single] imageId: ${imageId}`);
  allMessages.push(`🔍 [extract-text-single] timestamp: ${timestamp}`);
  //allMessages.push(`🔍 [extract-text-single] Image Data Array: ${JSON.stringify(imageData)}`);


  try {
    // Call formatDataToJson with all uploaded Cloudinary URLs
    const products = await formatDataToJson(
      uploadResults,
      storeId,
      userId,
      flyerBookId,
      postText, // Pass postText array if needed
      // Optionally add: postText, facebookUrl
      postId,
      imageId,
      timestamp // Pass timestamp if needed
    );


    console.log('✅ Formatted JSON from Gemini:', products);
    allMessages.push(`✅ Formatted JSON from Gemini: ${JSON.stringify(products)}`);

    res.json({
      cloudinaryUrls,
      products,
      allMessages,
      debug: {
        input: images,
        uploaded: cloudinaryUrls
      }
    });
  } catch (err) {
    console.error('❌ Error in /extract-text-single:', err);
    res.status(500).json({ error: 'Failed to process images', details: err.message });
  }
});

// ...existing code...





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

app.get('/initialize0', (req, res) => {
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


app.get('/initialize-anonymous', async (req, res) => {
  try {
    // Insert a new anonymous user into the database
    // The `userId` will be auto-incremented. Other fields are nullable.
    const [result] = await db.promise().query('INSERT INTO users () VALUES ()');
    
    const userId = result.insertId;
    if (!userId) {
      return res.status(500).json({ message: 'Failed to create anonymous user.' });
    }

    console.log(`[API] Created new anonymous user with ID: ${userId}`);

    // Create a long-lived token for the anonymous user
    const token = jwt.sign({ userId }, process.env.TOKEN_SECRET, { expiresIn: '2y' });

    res.json({ token });
  } catch (error) {
    console.error('[API] Error initializing anonymous session:', error);
    res.status(500).json({ message: 'Server error during initialization.' });
  }
});


// ...existing code...
app.get('/initialize', async (req, res) => { // Added async
  console.log('🟢 Initialize endpoint hit');

  // Check if user is already identified by the middleware
  if (req.identifiedUser && req.identifiedUser.userId) {
    console.log('✅ User already identified:', req.identifiedUser.userId);
    // Also send the token in the body for mobile clients that might need it
    const token = req.headers.authorization?.split(' ')[1] || req.cookies.jwt;
    return res.json({ message: 'User identified', userId: req.identifiedUser.userId, token });
  }

  // If no valid identified user, generate a new one
  console.log('⚠️ No valid user identified. Generating new anonymous user.');
  
  const anonymousUserId = `anon_${Date.now()}`;
  const tokenPayload = { userId: anonymousUserId };
  const token = jwt.sign(tokenPayload, process.env.TOKEN_SECRET, { expiresIn: '30d' });


  console.log('Generated Anonymous JWT:', token);

  try {
    // Insert placeholder for anonymous user
    const insertQuery = `
      INSERT INTO users (userId, first_name, is_registered)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE userId=userId`;
    await queryPromise(insertQuery, [anonymousUserId, `guest_${anonymousUserId}`, false]);

    // Set cookie for web clients
    res.cookie('jwt', token, {
        httpOnly: true,
        secure: true, 
        sameSite: 'None',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });

    console.log('✅ Anonymous user initialized. JWT cookie set for web. Token sent in body for mobile.');
    // Return the token in the body for the mobile app
    return res.json({ message: 'Anonymous user initialized', userId: anonymousUserId, token: token });

  } catch (err) {
      console.error('❌ Error inserting new anonymous user into database:', err);
      return res.status(500).json({ message: 'Failed to initialize anonymous user.' });
  }
});
// ...existing code...


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


app.post('/save-preferences',  (req, res) => {
  const { userId } = req.user;
  const { preferences } = req.body;
  res.json({ message: 'Preferences saved', userId, preferences });
});

app.get('/get-preferences',  (req, res) => {
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




async function insertProducts1(jsonData) {
  console.log('Insert products endpoint hit');
  console.log('JSON data received:', jsonData);
  console.log('JSON data type:', typeof jsonData);

  // Check if jsonData is already an object or array
  const products = Array.isArray(jsonData) ? jsonData : JSON5.parse(jsonData);
  console.log('Products received:', products);

  allMessages.push(`Insert products endpoint hit with ${products.length} products.`);
  allMessages.push(`JSON data type: ${typeof jsonData}`);

  if (!Array.isArray(products)) {
    console.error('Invalid JSON format:', products);
    allMessages.push('❌ Invalid JSON format received in insertProducts1');
    return; // Return without sending response as this is called from formatDataToJson
  }

  // if the array is empty, return without doing anything
  if (products.length === 0) {
    console.log('No products to insert, array is empty.');
    allMessages.push('No products to insert, array is empty.');
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
      const { product_description, old_price, new_price, discount_percentage, sale_end_date, storeId, keywords, image_url, category_id, flyer_book_id, postId , imageId, timestamp } = product;
      console.log('Processing product:', product);

       const dateObject = new Date(timestamp);
      const formattedTimestamp = dateObject.toISOString().slice(0, 19).replace('T', ' ');
      

      console.log('Product postId:', postId );

      console.log('timestamp insert product:', timestamp);
      

      allMessages.push(`Processing product with ImageId: ${imageId}`);
      allMessages.push(`timestamp in insert : ${timestamp}`);

      // make sure the old_price, new_price, are numbers , if not , convert them to numbers with decimal if needed to it can fit in the database
// if the price is missing or null set it to 0

      // --- FIX: Ensure prices are parsed as numbers before insertion ---
      const oldPriceNumber = old_price ? parseFloat(String(old_price).replace(',', '.').replace(/[^0-9.-]/g, '')) : 0;
      const newPriceNumber = new_price ? parseFloat(String(new_price).replace(',', '.').replace(/[^0-9.-]/g, '')) : 0;


            // --- FIX: Ensure imageId is treated as a number ---
      const numericImageId = parseInt(imageId, 10);
      if (isNaN(numericImageId)) {
          throw new Error(`Invalid numeric value for imageId: ${imageId}`);
      }

      allMessages.push(`Processing product with ImageId: ${numericImageId}`);
      allMessages.push(`timestamp in insert : ${formattedTimestamp}`);

     

      console.log('Image URL:', image_url);
      allMessages.push(`Image URL: ${image_url}`);


      const productResult = await dbQuery(
        `INSERT INTO products (product_description, old_price, new_price, discount_percentage, sale_end_date, storeId, image_url, category_id, flyer_book_id, postId, imageId , timestamp)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? , ?)`,
        [product_description, oldPriceNumber, newPriceNumber, discount_percentage, sale_end_date, storeId, image_url, category_id, flyer_book_id, postId, numericImageId, formattedTimestamp]
      );

      const productId = productResult.insertId;
      console.log('Inserted productId:', productId);
      allMessages.push(`Inserted productId: ${productId}`);

      if (!Array.isArray(keywords)) {
        console.log('Keywords is not an array:', keywords);
        allMessages.push(`❌ Keywords must be an array, received: ${typeof keywords}`);
        throw new Error('Keywords must be an array');
      }

      for (const keyword of keywords) {
        //console.log('Processing keyword:', keyword);
        //allMessages.push(`Processing keyword: ${keyword}`);
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
    allMessages.push('✅ All products and keywords inserted successfully!');
  } catch (err) {
    console.error('Error during product insertion:', err);
    allMessages.push(`❌ Error during product insertion: ${err.message}`);
    await dbQuery('ROLLBACK');
    console.error('Transaction rolled back due to error:', err);

    throw err;
  }
};




// write e function that takes image url and extracts sales end date from the image using Gemini 1.5 Pro 
// like in functon formatDataToJson but only for sale end date
// change the function to ba an api endpoint that takes image url and returns the sale end date in YYYY-MM-DD format




async function extractSaleEndDateFromImage(imageUrl) {
  console.log('🔍 Extracting sale end date from image using Gemini 1.5 Pro...')
  const geminiPrompt = `You are an AI assistant that specializes in extracting sale end dates from images of retail flyers.
  The flyer is in Albanian language and the sale end date is usually written in a specific Europen format.
Your task is to analyze the image, identify the sale end date, and return it in the format YYYY-MM-DD.  

Look for text patterns that indicate a date, such as "Sale ends on", "Valid until", or similar phrases.
Return the date in the format YYYY-MM-DD. If no date is found, return "No date found".`;
  console.log('Image URL:', imageUrl);

  const response = await generativeModel.generateContent({
    prompt: geminiPrompt,
    input: {
      image: {
        image_url: imageUrl, // Use the image URL directly
      },
    },
    response_format: {
      type: 'json',
      schema: {
        type: 'object',
        properties: {
          saleEndDate: {
            type: 'string',
            description: 'The extracted sale end date in YYYY-MM-DD format',
          },
        },
      },

    },
  });
  console.log('Response from Gemini:', response);
  const saleEndDate = response.candidates[0].content.saleEndDate;
  console.log('Extracted Sale End Date:', saleEndDate);
  return saleEndDate || 'No date found';
}


// ...existing code...

/**
 * Updated formatDataToJson to process each image individually:
 * - Loops through each image URL and makes a Gemini call for each image.
 * - Collects and returns all extracted product objects in a single array.
 * - Adds extensive debugging for each step and image.
 */
async function formatDataToJson(uploadResults, storeId, userId, flyerBookId, postText, postId, imageId, timestamp) {
  console.log('🔍 [formatDataToJson] Formatting data into JSON using Gemini 1.5 Pro (one image per call)...');
  console.log('Metadata received: Image URLs:', uploadResults, 'Store ID:', storeId, 'User ID:', userId, 'flyerBookId:', flyerBookId);  
  console.log('Image ID from formatDataToJson:', imageId); // Log imageId if provided

   allMessages.push('Metadata received: Image URLs:', uploadResults, 'Store ID:', storeId, 'User ID:', userId, 'flyerBookId:', flyerBookId);
  allMessages.push(`[formatDataToJson] Formatting data into JSON using Gemini 1.5 Pro (one image per call)...`);
 allMessages.push(`[formatDataToJson] Image URLs: ${JSON.stringify(uploadResults)}`);
 //for imageId 
  allMessages.push(`[formatDataToJson] Image ID: ${imageId}`); // Log imageId if provided


  // Get today's date in YYYY-MM-DD format
  const today = new Date();
  const formattedToday = today.toISOString().split('T')[0];
  const currentYear = today.getFullYear();


  // FORMAT timestmp UNIX TIME STAMP TO YYYY-MM-DD HH:mm:ss format
  //const date = new Date(timestamp * 1000); // Convert UNIX timestamp to milliseconds
  //const formattedTimestamp = date.toISOString().split('T')[0] + ' ' + date.toTimeString().split(' ')[0]; // Format to YYYY-MM-DD HH:mm:ss
  //const formattedTimestamp = new Date(timestamp).toISOString().split('T')[0];

 // const formattedTimestamp = new Date(timestamp * 1000);

  //const formattedTimestamp = date.toString()


    // --- FIX: Robust timestamp parsing ---
  let date;
  // Check if timestamp is a valid number (for UNIX timestamps)
  if (typeof timestamp === 'number' && !isNaN(timestamp)) {
    date = new Date(timestamp * 1000); // Convert UNIX timestamp to milliseconds
  } 
  // Check if timestamp is a non-empty string (for ISO strings)
  else if (typeof timestamp === 'string' && timestamp.trim() !== '') {
    date = new Date(timestamp);
  } 
  // Fallback if timestamp is null, undefined, or invalid
  else {
    console.warn(`[formatDataToJson] Invalid or missing timestamp received. Defaulting to current time.`);
    date = new Date();
  }

  // Final check to prevent crash if parsing still fails
  if (isNaN(date.getTime())) {
    console.error(`[formatDataToJson] CRITICAL: Failed to parse timestamp '${timestamp}'. Defaulting to current time to avoid crash.`);
    date = new Date();
  }

  const formattedTimestamp = date.toISOString().slice(0, 19).replace('T', ' ');
  // --- END FIX ---


  console.log(`[formatDataToJson] Formatted Timestamp: ${formattedTimestamp}`);

  allMessages.push(`[formatDataToJson] Formatted Today: ${formattedToday}`);
  allMessages.push(`[formatDataToJson] Processing ${uploadResults.length} images individually.`);
  allMessages.push(`[formatDataToJson] Formatted Timestamp: ${formattedTimestamp}`);

  let allProducts = [];

  for (let i = 0; i < uploadResults.length; i++) {
       const { uploadedUrl, imageId } = uploadResults[i];
    const url = uploadedUrl;
    const origUrl = uploadedUrl;
    console.log(`🔎 [formatDataToJson] Processing image #${i + 1}:`, url);

    // Compose the Gemini prompt for this image
    const geminiPrompt = 
    `You are an AI assistant that specializes in extracting structured product sale information from an image of an Albanian retail flyer extracted from Facebook Post.

Your task is to analyze the image, identify distinct product entries, and extract the product description, original price (if present), sale price, and discount percentage for each. A product entry typically consists of a product description and one or two prices. Original prices are usually higher and may be positioned near the sale price.

Analyze the visual layout and text content within the image to determine which elements belong to which product. 
Look for price patterns (numbers with currency symbols), percentage signs, and descriptive text.



Bellow is a caregories array with category ids, descriptions and weights. Based on the description of the product, 
you will assign a category_id to each product that best matches the description of the product
to the categoryDescription in may belong in the array given.

[
  {"categoryId": 100, "categoryDescription": "Fruits (Fruta)", "categoryWeight": 80},
  {"categoryId": 101, "categoryDescription": "Vegetables (Perime)", "categoryWeight": 80},
  {"categoryId": 102, "categoryDescription": "Herbs (Erëza të Freskëta)", "categoryWeight": 80},
  {"categoryId": 103, "categoryDescription": "Red Meat (Mish i Kuq)", "categoryWeight": 62},
  {"categoryId": 104, "categoryDescription": "Poultry (Shpendë)", "categoryWeight": 62},
  {"categoryId": 105, "categoryDescription": "Processed Meats (Mishra të Përpunuar)", "categoryWeight": 59},
  {"categoryId": 106, "categoryDescription": "Fresh Fish (Peshk i Freskët)", "categoryWeight": 38},
  {"categoryId": 107, "categoryDescription": "Frozen Fish & Seafood (Peshk dhe Fruta Deti të Ngrira)", "categoryWeight": 70},
  {"categoryId": 108, "categoryDescription": "Canned Fish (Peshk i Konservuar)", "categoryWeight": 65},
  {"categoryId": 109, "categoryDescription": "Milk (Qumësht)", "categoryWeight": 82},
  {"categoryId": 110, "categoryDescription": "Yogurt (Kos / Jogurt)", "categoryWeight": 82},
  {"categoryId": 111, "categoryDescription": "Cheese (Djathë)", "categoryWeight": 82},
  {"categoryId": 112, "categoryDescription": "Cream (Ajkë / Krem Qumështi)", "categoryWeight": 82},
  {"categoryId": 113, "categoryDescription": "Butter (Gjalpë)", "categoryWeight": 82},
  {"categoryId": 114, "categoryDescription": "Margarine & Spreads (Margarinë dhe Produkte për Lyerje)", "categoryWeight": 64},
  {"categoryId": 115, "categoryDescription": "Eggs (Vezë)", "categoryWeight": 82},
  {"categoryId": 116, "categoryDescription": "Bread (Bukë)", "categoryWeight": 71},
  {"categoryId": 117, "categoryDescription": "Pastries & Croissants (Pasta dhe Kroasante)", "categoryWeight": 71},
  {"categoryId": 118, "categoryDescription": "Cakes & Sweet Baked Goods (Kekë dhe Ëmbëlsira Furre)", "categoryWeight": 71},
  {"categoryId": 119, "categoryDescription": "Flour (Miell)", "categoryWeight": 47},
  {"categoryId": 120, "categoryDescription": "Rice (Oriz)", "categoryWeight": 65},
  {"categoryId": 121, "categoryDescription": "Pasta & Noodles (Makarona dhe Fide)", "categoryWeight": 65},
  {"categoryId": 122, "categoryDescription": "Grains & Cereals (Drithëra)", "categoryWeight": 66},
  {"categoryId": 123, "categoryDescription": "Sugar & Sweeteners (Sheqer dhe Ëmbëltues)", "categoryWeight": 47},
  {"categoryId": 124, "categoryDescription": "Salt & Spices (Kripë dhe Erëza)", "categoryWeight": 47},
  {"categoryId": 125, "categoryDescription": "Cooking Oils (Vajra Gatimi)", "categoryWeight": 64},
  {"categoryId": 126, "categoryDescription": "Vinegar (Uthull)", "categoryWeight": 64},
  {"categoryId": 127, "categoryDescription": "Canned Goods (Konserva)", "categoryWeight": 65},
  {"categoryId": 128, "categoryDescription": "Sauces & Condiments (Salca dhe Kondimente)", "categoryWeight": 64},
  {"categoryId": 129, "categoryDescription": "Spreads (Produkte për Lyerje)", "categoryWeight": 64},
  {"categoryId": 130, "categoryDescription": "Chips & Crisps (Çipsa dhe Patatina)", "categoryWeight": 76},
  {"categoryId": 131, "categoryDescription": "Pretzels & Salty Snacks (Shkopinj të Kripur dhe Rosto të Tjera)", "categoryWeight": 76},
  {"categoryId": 132, "categoryDescription": "Nuts & Seeds (Fruta të Thata dhe Fara)", "categoryWeight": 76},
  {"categoryId": 133, "categoryDescription": "Chocolate (Çokollatë)", "categoryWeight": 43},
  {"categoryId": 134, "categoryDescription": "Biscuits & Cookies (Biskota dhe Keksa)", "categoryWeight": 76},
  {"categoryId": 135, "categoryDescription": "Candies & Gums (Karamele dhe Çamçakëz)", "categoryWeight": 43},
  {"categoryId": 136, "categoryDescription": "Frozen Vegetables & Fruits (Perime dhe Fruta të Ngrira)", "categoryWeight": 70},
  {"categoryId": 137, "categoryDescription": "Frozen Potato Products (Produkte Patatesh të Ngrira)", "categoryWeight": 70},
  {"categoryId": 138, "categoryDescription": "Frozen Ready Meals & Pizza (Gatime të Gata dhe Pica të Ngrira)", "categoryWeight": 70},
  {"categoryId": 139, "categoryDescription": "Frozen Meat & Fish (Mish dhe Peshk i Ngrirë)", "categoryWeight": 70},
  {"categoryId": 140, "categoryDescription": "Ice Cream (Akullore)", "categoryWeight": 70},
  {"categoryId": 141, "categoryDescription": "Baby Food (Ushqim për Foshnje)", "categoryWeight": 7},
  {"categoryId": 142, "categoryDescription": "Baby Formula (Qumësht Formule)", "categoryWeight": 7},
  {"categoryId": 143, "categoryDescription": "Water (Ujë)", "categoryWeight": 53},
  {"categoryId": 144, "categoryDescription": "Still Water (Ujë Natyral / pa Gaz)", "categoryWeight": 53},
  {"categoryId": 145, "categoryDescription": "Sparkling Water (Ujë Mineral / me Gaz)", "categoryWeight": 53},
  {"categoryId": 146, "categoryDescription": "Flavored Water (Ujë me Shije)", "categoryWeight": 53},
  {"categoryId": 147, "categoryDescription": "Fruit Juices (Lëngje Frutash)", "categoryWeight": 53},
  {"categoryId": 148, "categoryDescription": "Nectars (Nektare)", "categoryWeight": 53},
  {"categoryId": 149, "categoryDescription": "Smoothies (Smoothie)", "categoryWeight": 53},
  {"categoryId": 150, "categoryDescription": "Colas (Kola)", "categoryWeight": 53},
  {"categoryId": 151, "categoryDescription": "Other Carbonated Drinks (Pije të Tjera të Gazuara)", "categoryWeight": 53},
  {"categoryId": 152, "categoryDescription": "Coffee (Kafe)", "categoryWeight": 53},
  {"categoryId": 153, "categoryDescription": "Tea (Çaj)", "categoryWeight": 53},
  {"categoryId": 154, "categoryDescription": "Energy Drinks (Pije Energjetike)", "categoryWeight": 53},
  {"categoryId": 155, "categoryDescription": "Alcoholic Beverages (Pije Alkoolike)", "categoryWeight": 29},
  {"categoryId": 156, "categoryDescription": "Beer (Birrë)", "categoryWeight": 29},
  {"categoryId": 157, "categoryDescription": "Wine (Verë)", "categoryWeight": 29},
  {"categoryId": 158, "categoryDescription": "Spirits (Pije Spirtuore)", "categoryWeight": 29},
  {"categoryId": 159, "categoryDescription": "Laundry Detergents (Detergjentë Rrobash)", "categoryWeight": 59},
  {"categoryId": 160, "categoryDescription": "Fabric Softeners (Zbutës Rrobash)", "categoryWeight": 59},
  {"categoryId": 161, "categoryDescription": "Dishwashing Products (Produkte për Larjen e Enëve)", "categoryWeight": 59},
  {"categoryId": 162, "categoryDescription": "Surface Cleaners (Pastrues Sipërfaqesh)", "categoryWeight": 59},
  {"categoryId": 163, "categoryDescription": "Toilet Cleaners (Pastrues WC)", "categoryWeight": 59},
  {"categoryId": 164, "categoryDescription": "Garbage Bags (Thasë Mbeturinash)", "categoryWeight": 59},
  {"categoryId": 165, "categoryDescription": "Soaps & Shower Gels (Sapunë dhe Xhel Dushi)", "categoryWeight": 50},
  {"categoryId": 166, "categoryDescription": "Shampoos & Conditioners (Shampon dhe Balsam Flokësh)", "categoryWeight": 50},
  {"categoryId": 167, "categoryDescription": "Oral Care (Kujdesi Oral)", "categoryWeight": 50},
  {"categoryId": 168, "categoryDescription": "Deodorants & Antiperspirants (Deodorantë)", "categoryWeight": 50},
  {"categoryId": 169, "categoryDescription": "Skin Care (Kujdesi i Lëkurës)", "categoryWeight": 50},
  {"categoryId": 170, "categoryDescription": "Feminine Hygiene (Higjiena Femërore)", "categoryWeight": 50},
  {"categoryId": 171, "categoryDescription": "Paper Products (Produkte Letre)", "categoryWeight": 59},
  {"categoryId": 172, "categoryDescription": "Baby Diapers & Wipes (Pelena dhe Letra të Lagura për Foshnje)", "categoryWeight": 7},
  {"categoryId": 173, "categoryDescription": "Other", "categoryWeight": 1}
]       



Extract the sale end dates either from the given post text: "${postText || ''}" or from the image itself. Return it in the format YYYY-MM-DD.
If there are multiple dates, return the latest one. If the year is missing, use the current year (${currentYear}). If the sale end date is missing, use today's date: ${formattedToday}.
Format the date in form "YYYY-MM-DD". If sale end date is less than ${formattedToday}, set valid_product to false.
Populate the sale_end_date field with the sale date found.

For each distinct product entry you identify in the image, create a JSON object in your output array with these exact keys and data types:

* \`product_description\` (string): The complete descriptive text associated with the product in the flyer. Include any size/volume information (e.g., 0,33L, 400ml, 3kg) if it's part of the product's description text in the flyer.
* \`old_price\` (string or null): The text of the original price (if a higher price is present). Remove currency symbols (€). If no distinct original price is found for a product, use \`null\`.
* \`new_price\` (string or null): The text of the current sale price (the lower price). Remove currency symbols (€). If no sale price is found, use \`null\`.
* \`discount_percentage\` (string or null): The numerical value of the discount percentage shown (e.g., "14"). Remove the percentage symbol (%). If no discount percentage is found, use \`null\`.
* \`sale_end_date\` (string): Use the extracted value from the flyer or post text. Format as "YYYY-MM-DD".
* \`storeId\` (number): Use the provided value: ${storeId}.
* \`userId\` (number): Use the provided value: ${userId}.
* \`postId\` (number): Use the provided value: ${postId}.
* \`imageId\` (number): Use the provided value: ${imageId}.
* \`timestamp\` (timestamp): Use the provided value: ${formattedTimestamp}.
* \`image_url\` (string): Use the current url of the image being processed store in ${url}.

* \`category_id\` (number or null): The numerical value of the categoryId extract from categories array.
*\`flyer_book_id\` (number or null): Use the provided value: "${flyerBookId}".
*\`valid_product\` (true or false): A boolean indicating if the product is valid based on the following criteria:
  - The product description must not be empty.
  - At least one of the prices (old_price or new_price) must be present.
  - The sale_end_date must be a valid date in the future (after today).

Also, generate a list of relevant keywords for each product description. These keywords should be in lowercase, in Albanian, 
and exclude common articles, conjunctions, prepositions, and size/volume information (like 'kg', 'l', 'pako', numbers, units). 
Only include words longer than 2 characters. Convert the Albanian letter 'ë' to 'e' for all keywords. 
If there is a keyword like "qumesht" or "qumësht" add a keyword "qumsht" as well to cover both spellings.
if there is a keyword like "veze" add a keyword "vo" as well to cover both spellings.
if there is a keyword like "shalqi*" add a keyword "bostan" as well to cover both spellings.
if there is a keyword like "ver*" add a keyword "vene" as well to cover both spellings.
if there is a keyword like "qepe" add a keyword "kep" as well to cover both spellings.
The \`keywords\` field should be an array of strings. Limit the keywords to the most relevant 5 per product.

Provide ONLY the JSON array of extracted product objects in your response. Do not include any introductory or concluding text, explanations, or code block markers. Ensure the output is valid JSON.
`;

    try {
      // Prepare Gemini Vision API input for this image
      const imagePart = {
        fileData: {
          mimeType: 'image/jpeg',
          fileUri: url,
        }
      };

      const contents = [
        {
          role: 'user',
          parts: [
            { text: geminiPrompt },
            imagePart
          ],
        },
      ];

      const response = await generativeModel.generateContent({
        contents,
      });

      let text = response.response.candidates[0].content.parts[0].text;

      console.log(`[formatDataToJson] Raw Gemini Output for image #${i + 1}:`, text);
      allMessages.push(`[formatDataToJson] Raw Gemini Output for image #${i + 1}: ${text}`);

      // Clean up potential markdown code block and backticks
      text = text.replace(/^```json\s*/, '').replace(/\s*```$/, '').replace(/`/g, '');

      try {
        const products = JSON5.parse(text);
        console.log(`[formatDataToJson] Parsed JSON for image #${i + 1}:`, products);
        allMessages.push(`[formatDataToJson] Parsed JSON for image #${i + 1}: ${JSON.stringify(products)}`);

        // Filter out invalid products
        const validProducts = Array.isArray(products)
          ? products.filter(product => product.valid_product !== false)
          : [];

          allMessages.push(`[formatDataToJson] Valid products extracted for image #${i + 1}: ${validProducts}`);

        // Call the insertion function with the parsed products array
        if (validProducts.length > 0) {
          await insertProducts1(validProducts);
        }

        allProducts = allProducts.concat(validProducts);

      } catch (parseError) {
        console.error(`[formatDataToJson] JSON Parsing Error for image #${i + 1}:`, parseError);
        console.error(`[formatDataToJson] Failed JSON Text for image #${i + 1}:`, text);
        allMessages.push(`[formatDataToJson] JSON Parsing Error for image #${i + 1}: ${parseError.message}`);
      }

    } catch (error) {
      console.error(`[formatDataToJson] Gemini API Error for image #${i + 1}:`, error);
      if (error.details) {
        console.error('[formatDataToJson] Gemini API Error Details:', error.details);
      }
      if (error.message && error.message.includes("400 Bad Request")) {
        console.error("[formatDataToJson] Possible issue: Incorrect file type or URL for Gemini Vision input.");
      }
      allMessages.push(`[formatDataToJson] Gemini API Error for image #${i + 1}: ${error.message}`);
    }
  }

  console.log('[formatDataToJson] All extracted products:', allProducts);
  allMessages.push(`[formatDataToJson] All extracted products: ${JSON.stringify(allProducts)}`);

  return allProducts;
}

// ...existing code...


// **UPDATED** formatDataToJson function to work with image URL
 






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
  const q = `SELECT * from stores WHERE facebookPageId > 0 and active = true order by storeId asc`;
  const userId= req.query.userId;
    db.query(q, (err, data) => {
    if (err) {
      console.log("getStores error:", err);
      return res.json(err);
    }
    return res.json(data);
  });
});



app.get("/getFaceBookStores", (req, res) => {
  const q = `SELECT * from stores order by storeId WHERE facebookPageId NOT NULL asc`;
  const userId= req.query.userId;
    db.query(q, (err, data) => {
    if (err) {
      console.log("getStores error:", err);
      return res.json(err);
    }
    return res.json(data);
  });
});




// api to get all the image_url that have the same flyer_book_id 

app.get("/getImagesByFlyerBookId", (req, res) => {

  const flyerBookId = req.query.flyerBookId;

  // SELECT ONLY DISTINCT image_url FROM products WHERE flyer_book_id = ?

  const q = `SELECT DISTINCT image_url FROM products WHERE flyer_book_id = ?`;

  db.query(q, [flyerBookId], (err, data) => {
    if (err) {
      console.log("getImagesByFlyerBookId error:", err);
      return res.json(err);
    }
    return res.json(data);
  }
  );
});



app.get("/isFavorite", async (req, res) => { // Added async
  // Allow checking even if not identified, will just return false
  const userId = req.identifiedUser ? req.identifiedUser.userId : null;
  const { productId } = req.query;

  if (!userId || !productId) {
     // Cannot check favorite without user and product ID
     // Technically could check productId only, but usually it's user-specific
     return res.status(200).json({ isFavorite: false }); // Return false if no user or product ID
  }

  const q = `SELECT favoriteId FROM favorites WHERE userId = ? AND productId = ?`;
  try {
      const result = await queryPromise(q, [userId, productId]);
      const isFavorite = result.length > 0;
      res.status(200).json({ isFavorite });
  } catch (err) {
      console.error('Error checking favorite:', err);
      return res.status(500).json({ error: 'Failed to check favorite status' });
  }
});


// ...existing code...

app.post('/register-push-token', identifyUserMiddleware, async (req, res) => {
  const { token } = req.body;
  // IMPORTANT: Use the integer `id` from the user object, not the varchar `userId`.
  //const userId = req.identifiedUser?.id;
  const userId = req.identifiedUser?.userId;

    console.log(`[Push] Attempting to register token for user ID: ${userId}`);

  if (!userId || !token) {
    return res.status(400).json({ error: 'User ID and token are required.' });
  }

  if (!Expo.isExpoPushToken(token)) {
    console.error(`Push token ${token} is not a valid Expo push token.`);
    return res.status(400).json({ error: 'Invalid push token.' });
  }

  try {
    const q = 'INSERT INTO push_tokens (user_id, token) VALUES (?, ?) ON DUPLICATE KEY UPDATE user_id = VALUES(user_id)';
    await queryPromise(q, [userId, token]);
    console.log(`[Push] Registered token for user ${userId}`);
    res.status(200).json({ message: 'Token registered successfully.' });
  } catch (err) {
    console.error('[Push] Error registering token:', err);
    res.status(500).json({ error: 'Failed to register token.' });
  }
});

// ...existing code...



app.get('/user/preferences', async (req, res) => {
  if (!req.identifiedUser?.userId) {
    return res.status(401).json({ error: 'User identification required.' });
  }
  try {


    console.log(`[API] Getting user preferences for User ID: ${req.identifiedUser.userId}`);


    const q = 'SELECT first_name, last_name, email, notification_frequency FROM users WHERE id = ?';
    const [user] = await queryPromise(q, [req.identifiedUser.userId]);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }
    res.json({ 
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email,
      notificationFrequency: user.notification_frequency });
  } catch (err) {
    console.error('[API] Error getting user preferences:', err);
    res.status(500).json({ error: 'Failed to get preferences.' });
  }
});

// PUT (update) notification preference
app.put('/user/preferences', async (req, res) => {
  if (!req.identifiedUser?.userId) {
    return res.status(401).json({ error: 'User identification required.' });
  }
  const { notificationFrequency } = req.body;
  const validFrequencies = ['daily', 'weekly', 'monthly', 'off'];

  if (!validFrequencies.includes(notificationFrequency)) {
    return res.status(400).json({ error: 'Invalid notification frequency value.' });
  }

  try {
    const q = 'UPDATE users SET notification_frequency = ? WHERE id = ?';
    await queryPromise(q, [notificationFrequency, req.identifiedUser.userId]);
    res.json({ message: 'Preferences updated successfully.' });
  } catch (err) {
    console.error('[API] Error updating user preferences:', err);
    res.status(500).json({ error: 'Failed to update preferences.' });
  }
});


// GET user profile information
app.get('/user/profile', async (req, res) => {
  if (!req.identifiedUser?.userId) {
    return res.status(401).json({ error: 'User identification required.' });
  }
  try {
    console.log(`[API] Getting user profile for User ID: ${req.identifiedUser.userId}`);
    const q = 'SELECT first_name, last_name, email, notification_frequency FROM users WHERE id = ?';
    const [user] = await queryPromise(q, [req.identifiedUser.userId]);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }
    res.json({ 
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email,
      notificationFrequency: user.notification_frequency 
    });
  } catch (err) {
    console.error('[API] Error getting user profile:', err);
    res.status(500).json({ error: 'Failed to get profile.' });
  }
});

// PUT (update) user profile information
app.put('/user/profile', async (req, res) => {
  if (!req.identifiedUser?.userId) {
    return res.status(401).json({ error: 'User identification required.' });
  }
  
  const { firstName, lastName, email, notificationFrequency } = req.body;
  const validFrequencies = ['daily', 'weekly', 'monthly', 'off'];

  if (notificationFrequency && !validFrequencies.includes(notificationFrequency)) {
    return res.status(400).json({ error: 'Invalid notification frequency value.' });
  }

  try {
    const q = `
      UPDATE users 
      SET first_name = ?, last_name = ?, email = ?, notification_frequency = ? 
      WHERE id = ?
    `;
    await queryPromise(q, [
      firstName, 
      lastName, 
      email, 
      notificationFrequency, 
      req.identifiedUser.userId
    ]);
    res.json({ message: 'Profile updated successfully.' });
  } catch (err) {
    console.error('[API] Error updating user profile:', err);
    res.status(500).json({ error: 'Failed to update profile.' });
  }
});


// --- NEW: Push Notification Test Endpoint ---
app.post('/test-push', async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'User ID is required.' });
  }

  console.log(`[Push Test] Received request to send test notification to User ID: ${userId}`);

  try {
    // 1. Get the push tokens for the specified user
    const tokenResults = await queryPromise('SELECT token FROM push_tokens WHERE user_id = ?', [userId]);
    
    if (tokenResults.length === 0) {
      console.log(`[Push Test] No push tokens found for User ID: ${userId}`);
      return res.status(404).json({ message: 'No push tokens found for this user.' });
    }

    const tokens = tokenResults.map(row => row.token);
    console.log(`[Push Test] Found ${tokens.length} token(s). Preparing to send...`);

    // 2. Create the notification message
    const messages = [];
    for (const pushToken of tokens) {
      if (!Expo.isExpoPushToken(pushToken)) {
        console.error(`Push token ${pushToken} is not a valid Expo push token.`);
        continue;
      }
      messages.push({
        to: pushToken,
        sound: 'default',
        title: '✅ Test Njoftimi',
        body: `Ky është një test nga serveri për User ID: ${userId}`,
        data: { withSome: 'data' },
      });
    }

    // 3. Send the notifications
    const expo = new Expo({ useFcmV1: true });
    const chunks = expo.chunkPushNotifications(messages);
    const tickets = [];

    console.log('[Push Test] Sending notification chunks to Expo...');
    for (let chunk of chunks) {
      try {
        let ticketChunk = await expo.sendPushNotificationsAsync(chunk);
        console.log('[Push Test] Received ticket chunk:', ticketChunk);
        tickets.push(...ticketChunk);
      } catch (error) {
        console.error('[Push Test] Error sending push notification chunk:', error);
      }
    }
    console.log('[Push Test] All chunks sent. Awaiting receipts...');

    // --- NEW: Part 2 - Process the receipts ---
    // Later, after the Expo push notification service has delivered the
    // notifications to Apple or Google (usually quickly), you can get
    // the receipts for each notification and check for errors.
    let receiptIds = [];
    for (let ticket of tickets) {
      // NOTE: Not all tickets have IDs; for example, tickets for notifications
      // that could not be sent will have error information and no receipt ID.
      if (ticket.id) {
        receiptIds.push(ticket.id);
      }
    }

    let receiptIdChunks = expo.chunkPushNotificationReceiptIds(receiptIds);
    for (let chunk of receiptIdChunks) {
      try {
        let receipts = await expo.getPushNotificationReceiptsAsync(chunk);
        console.log('[Push Test] Received receipts:', receipts);

        // The receipts object is a map of ticket IDs to receipt objects.
        for (let receiptId in receipts) {
          let { status, message, details } = receipts[receiptId];
          if (status === 'ok') {
            continue;
          } else if (status === 'error') {
            console.error(
              `[Push Test] ❌ There was an error sending a notification: ${message}`
            );
            if (details && details.error) {
              // The error codes are listed in the Expo documentation:
              // https://docs.expo.dev/push-notifications/sending-notifications/#individual-errors
              // E.g., "DeviceNotRegistered" means you probably need to remove the token from your database.
              console.error(`[Push Test] ❌ Error details:`, details);
            }
          }
        }
      } catch (error) {
        console.error('[Push Test] Error getting push receipts:', error);
      }
    }

    res.status(200).json({ message: 'Test notification request processed. Check server logs for details.' });

  } catch (error) {
    console.error('[Push Test] Error processing test notification request:', error);
    res.status(500).json({ error: 'Failed to process test notification request.' });
  }
});


app.post("/addFavorite", async (req, res) => { // Added async

  console.log('Add favorite endpoint hit...');

  
  // The user MUST be identified by the middleware to add a favorite.
  if (!req.identifiedUser || !req.identifiedUser.userId) {
    console.error('[API] Error: User identification is required to add a favorite.');
    return res.status(401).json({ error: 'User identification required.' });
  }

  const { userId } = req.identifiedUser;
  const { productId } = req.body;

  console.log(`[API] Adding favorite for User ID: ${userId} and Product ID: ${productId}`);

  if (!productId) {
     return res.status(400).json({ error: 'Product ID is required.' });
  }

  const q = `INSERT IGNORE INTO favorites (userId, productId) VALUES (?, ?)`; // Use INSERT IGNORE

  try {
      await queryPromise(q, [userId, productId]);
      res.status(200).json({ message: 'Favorite added successfully (or already existed)' });
  } catch (err) {
       console.error('Error adding favorite:', err);
       return res.status(500).json({ error: 'Failed to add favorite' });
  }
});

app.delete("/removeFavorite", async (req, res) => { // Added async
  if (!req.identifiedUser || !req.identifiedUser.userId) {
    return res.status(401).json({ error: 'User identification required to remove favorites.' });
  }
  const { userId } = req.identifiedUser;

  console.log(`[API] Removing favorite for User ID: ${userId}`);

  // Get productId from request body OR query parameters
  const productId = req.body.productId || req.query.productId;

   if (!productId) {
     return res.status(400).json({ error: 'Product ID is required.' });
  }

  const q = `DELETE FROM favorites WHERE userId = ? AND productId = ?`;
  try {
      await queryPromise(q, [userId, productId]);
      console.log(`[API] Favorite removed for User ID: ${userId} and Product ID: ${productId}`);
      res.status(200).json({ message: 'Favorite removed successfully' });
  } catch (err) {
       console.error('Error removing favorite:', err);
       return res.status(500).json({ error: 'Failed to remove favorite' });
  }
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

// Endpoint to get TOP 100 products and keyword associated with products

app.get("/getProductsWithKeywords", (req, res) => {
  const q = `



    SELECT
      p.productId,
      p.product_description,
      p.old_price,
      p.new_price,
      p.discount_percentage,
      p.sale_end_date,
      p.storeId,
      p.image_url,
      GROUP_CONCAT(k.keyword SEPARATOR ', ') AS keywords
    FROM
      products p
    LEFT JOIN
      productkeywords pk ON p.productId = pk.productId
    LEFT JOIN
      keywords k ON pk.keywordId = k.keywordId
    GROUP BY
      p.productId

    ORDER BY
      p.productId desc

LIMIT 100
  `;
  db.query(q, (err, data) => {
    if (err) {
      console.error('Error fetching products with keywords:', err);
      return res.status(500).json({ error: 'Failed to fetch products with keywords' });
    }


    console.log('Fetched products with keywords:', data);

    return res.json(data);
  });
});



app.get("/getProducts", async (req, res) => {
  console.log('getProducts endpoint hit');
  const userId = req.identifiedUser ? req.identifiedUser.userId : null;

  // Support single storeId OR comma-separated list of storeIds (client may send CSV)
  const storeIdsParam = req.query.storeId || req.query.storeIds || "";
  let storeIds = null;
  if (storeIdsParam && typeof storeIdsParam === "string") {
    const parsed = storeIdsParam
      .split(",")
      .map((s) => parseInt(s.trim(), 10))
      .filter(Number.isFinite);
    if (parsed.length > 0) storeIds = parsed; // array of integers
  }

  const isFavoriteQueryParam = req.query.isFavorite === 'true';
  const onSale = req.query.onSale === 'true';
  const keywordQuery = req.query.keyword || null; // Renamed to avoid conflict with table alias 'k'
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const offset = (page - 1) * limit;
  const today = new Date().toISOString().split('T')[0];

  // --- MODIFICATION START: Prepare for matched_keyword_count ---
  const searchKeywordsArray = keywordQuery ? keywordQuery.split(' ').map(kw => kw.trim()).filter(kw => kw.length > 1) : [];
  let matchedKeywordCountSelectSQL = '0 AS matched_keyword_count'; // Default value
  const paramsForMatchedKeywordCountSubquery = []; // Parameters for the subquery in SELECT

  if (searchKeywordsArray.length > 0) {
    const matchConditionsForSubquery = searchKeywordsArray.map(() => `sk_match.keyword LIKE ?`).join(' OR ');
    matchedKeywordCountSelectSQL = `
      (
        SELECT COUNT(DISTINCT sk_match.keywordId)
        FROM productkeywords pk_match
        JOIN keywords sk_match ON pk_match.keywordId = sk_match.keywordId
        WHERE pk_match.productId = p.productId AND (${matchConditionsForSubquery})
      ) AS matched_keyword_count
    `;
    searchKeywordsArray.forEach(kw => paramsForMatchedKeywordCountSubquery.push(`${kw}%`));
  }
  // --- Modification end ---

  let fromAndJoins = `
    FROM
      products p
    LEFT JOIN stores s ON p.storeId = s.storeId
    LEFT JOIN productkeywords pk ON p.productId = pk.productId
    LEFT JOIN productcategories pc ON p.category_id = pc.categoryId
    LEFT JOIN keywords k ON pk.keywordId = k.keywordId
    ${userId ? `LEFT JOIN favorites f ON p.productId = f.productId AND f.userId = ?` : ''}
  `;

  // Main SELECT statement including the dynamic matched_keyword_count
  let q = `
    SELECT
      p.productId, p.product_description, p.old_price, p.new_price,
      p.discount_percentage, p.sale_end_date, p.storeId, p.image_url,
      s.storeName, s.logoUrl, p.flyer_book_id,
      ANY_VALUE(pc.categoryWeight) AS categoryWeight,
      GROUP_CONCAT(DISTINCT k.keyword SEPARATOR ',') AS keywords,
      ${matchedKeywordCountSelectSQL},
      ${userId ? 'CASE WHEN f.userId IS NOT NULL THEN TRUE ELSE FALSE END' : 'FALSE'} AS isFavorite,
      CASE WHEN p.sale_end_date >= ? THEN TRUE ELSE FALSE END AS productOnSale
    ${fromAndJoins}
  `;

  // Build parameters for the SELECT part first
  const selectParams = [];
  selectParams.push(...paramsForMatchedKeywordCountSubquery); // Params for the subquery
  selectParams.push(today); // For productOnSale CASE WHEN
  if (userId) {
    selectParams.push(userId); // For isFavorite CASE WHEN (and the JOIN if userId is present)
  }

  // Build WHERE clause conditions and parameters
  let conditions = [];
  const whereParams = [];

  // If storeIds is an array use IN(...) ; otherwise no store filter
  if (Array.isArray(storeIds) && storeIds.length > 0) {
    const placeholders = storeIds.map(() => '?').join(',');
    conditions.push(`p.storeId IN (${placeholders})`);
    whereParams.push(...storeIds);
  }

  if (isFavoriteQueryParam && userId) {
    conditions.push(`EXISTS (SELECT 1 FROM favorites fav_sub WHERE fav_sub.productId = p.productId AND fav_sub.userId = ?)`);
    whereParams.push(userId); // This userId is for the EXISTS subquery condition
  }

  if (onSale) {
    conditions.push(`p.sale_end_date >= ?`);
    whereParams.push(today);
  }

  if (searchKeywordsArray.length > 0) {
    // These conditions are for filtering rows (WHERE clause)
    const keywordTableConditions = searchKeywordsArray.map(() => `k.keyword LIKE ?`).join(' OR ');
    const descriptionConditions = searchKeywordsArray.map(() => `p.product_description LIKE ?`).join(' OR ');
    conditions.push(`((${keywordTableConditions}) OR (${descriptionConditions}))`);
    searchKeywordsArray.forEach(kw => whereParams.push(`${kw}%`)); // Params for k.keyword in WHERE
    searchKeywordsArray.forEach(kw => whereParams.push(`${kw}%`)); // Params for p.product_description in WHERE
  }

  if (conditions.length > 0) {
    q += ' WHERE ' + conditions.join(' AND ');
  }

  // Add GROUP BY, ORDER BY, and LIMIT/OFFSET
  q += `
    GROUP BY p.productId ${matchedKeywordCountSelectSQL !== '0 AS matched_keyword_count' ? '' : ''} 
    ORDER BY matched_keyword_count DESC,  productOnSale DESC , categoryWeight DESC, p.productId DESC
    LIMIT ? OFFSET ?
  `;

  // Combine all parameters in the correct order
  const finalParams = [...selectParams, ...whereParams, limit, offset];

  try {
    const data = await queryPromise(q, finalParams);
    const nextPage = data.length === limit ? page + 1 : null;
    return res.json({ data, nextPage });
  } catch(err) {
    console.log("getProducts error:", err);
    return res.status(500).json({ error: "Failed to retrieve products" });
  }
});
// ...existing code...

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
    const uploadPromises = req.files.map(async file => {
      const imagePath = file.path;
      // convert to WebP on upload:
      const result = await cloudinary.uploader.upload(imagePath, {
        folder: req.body.folderName || 'default-folder',
        use_filename: true,
        unique_filename: false,
        overwrite: true,
        transformation: [
          // first you can cap size if you like:
          // { width: 2000, crop: 'limit' },
          // then *actually* convert:
          { fetch_format: 'webp', quality: 'auto' }
        ]
      });
      fs.unlinkSync(imagePath);
      return {
        success: true,
        url: result.secure_url,  // this is .webp
        public_id: result.public_id,
        format: result.format    // should be 'webp'
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
  // console log the ip address of the machine
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        console.log(`Server IP address: http://${iface.address}:${port}`);
      }
    }
  }
});