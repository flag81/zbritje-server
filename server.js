
import multer from 'multer';
import cloudinary from './cloudinaryConfig.js';
import cors from 'cors';
import fs from 'fs';
import dotenv from 'dotenv';



dotenv.config();

import express from 'express';

import { fileURLToPath } from "url";
import path from "path";

import vision from '@google-cloud/vision';

import JSON5 from 'json5';

//const { VertexAI } = require('@google-cloud/vertexai');

// convert above to import



 

//keyFilename: path.join(__dirname, './vision-ai-455010-d952b6232600.json'), // Replace with your key file path



const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const keyFilePath = path.join(__dirname, './persistent/keys/vision-ai-455010-6d2a9944437b.json');

//change keyFilePath to come from variable in .env file

process.env.GOOGLE_APPLICATION_CREDENTIALS = keyFilePath;

if (!fs.existsSync(keyFilePath)) {
  console.error('❌ Key file not found:', keyFilePath);
 
}
else {

  console.log('✅ Key file found:', keyFilePath);
}

const credentials = JSON.parse(fs.readFileSync(keyFilePath, 'utf8'));


console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID);
console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET);



import { VertexAI } from '@google-cloud/vertexai';

const vertexAI = new VertexAI({project: 'vision-ai-455010', location: 'us-central1'}); // Replace with your project and location

  // check if key file exists and load it

  console.log('✅ VertexAI client initialized in server.js'); // Add this


  console.log('Attempting to load key file from:', keyFilePath);



// Load private key for Apple authentication
const privateKeyPath = path.join(__dirname, "./persistent/keys/AuthKey_6YK9NFRYH9.p8"); // Path to your .p8 key file
const privateKey = fs.readFileSync(privateKeyPath, "utf8");

//console.log('privateKey:', privateKey);

const client = new vision.ImageAnnotatorClient({
  keyFilename: path.join(__dirname, './persistent/keys/vision-ai-455010-6d2a9944437b.json'), // Replace with your key file path
});



import { format } from 'path';
import db from './connection.js';

import cookieParser from 'cookie-parser';
import bodyParser from'body-parser';

import AppleSigninAuth from 'apple-signin-auth';

import OpenAI from "openai";
const openai = new OpenAI();

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




// Apple Sign-In Route
app.get(
  "/auth/apple222",
  passport.authenticate("apple", { scope: ["email", "name"] }),

  (req, res) => {
    console.log("🍏 Apple OAuth Callback Triggered");
  }
  
);

// Apple Sign-In Route (Redirects to Apple Auth)
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

// **Apple Callback Handler**
app.post("/auth/apple/callback", async (req, res) => {
  try {
    console.log("🍏 Apple OAuth Callback Triggered");

    const { code, id_token } = req.body;

    if (!code && !id_token) {
      console.error("❌ No authorization code or ID token received.");
      return res.status(400).json({ error: "Missing Apple authorization data" });
    }

    let decodedToken;

    // If ID token is available, decode it directly (short path)
    if (id_token) {
      decodedToken = jwt.decode(id_token);
    } else {
      // Exchange the authorization code for an access token
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

    const appleId = decodedToken.sub; // Apple's unique user identifier
    let email = decodedToken.email || null; // Email may be missing

    console.log(`🍏 Received AppleID: ${appleId}, Email: ${email || "No email provided"}`);

    // **Step 1: Check if the user exists in the database**
    const checkQuery = `SELECT userId, email FROM users WHERE userId = ? OR email = ?`;
    db.query(checkQuery, [appleId, email], (err, results) => {
      if (err) {
        console.error("❌ Database error:", err);
        return res.status(500).json({ error: "Database error" });
      }

      if (results.length > 0) {
        // ✅ **Existing user found**
        const existingUser = results[0];
        console.log(`✅ Existing user found: userId=${existingUser.userId}, email=${existingUser.email || "No email"}`);

        // **Step 2: Update email if missing**
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

        // **Step 3: Generate JWT for existing user**
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
        // 🆕 **New user - Insert into database**
        console.log(`🆕 New user detected, inserting: ${email || "No email provided"} and AppleID: ${appleId}`);

        const insertQuery = `INSERT INTO users (userName, email) VALUES (?, ?)`;
        db.query(insertQuery, [appleId, email], (insertErr) => {
          if (insertErr) {
            console.error("❌ Error inserting new user:", insertErr);
            return res.status(500).json({ error: "Failed to insert new user" });
          }

          console.log(`✅ New user inserted: AppleID=${appleId}, Email=${email || "No email"}`);

          // **Step 4: Generate JWT for new user**
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

    // extract email and Apple ID
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

      const { id_token } = req.body; // Apple sends `id_token`
      if (!id_token) {
          console.error("❌ No ID token received.");
          return res.status(400).json({ error: "Missing ID token" });
      }

      // Fetch Apple's public keys for verification
      const appleKeys = await axios.get("https://appleid.apple.com/auth/keys");
      const applePublicKeys = appleKeys.data.keys;

      // Decode JWT header to get the key ID
      const decodedHeader = jwt.decode(id_token, { complete: true });
      if (!decodedHeader) {
          console.error("❌ Failed to decode Apple ID token.");
          return res.status(400).json({ error: "Invalid ID token" });
      }

      // Find the matching key
      const key = applePublicKeys.find(k => k.kid === decodedHeader.header.kid);
      if (!key) {
          console.error("❌ No matching Apple key found.");
          return res.status(400).json({ error: "Invalid Apple key" });
      }

      // Verify ID Token
      const verifiedPayload = jwt.verify(id_token, jwt.jwkToPem(key), { algorithms: ["RS256"] });
      console.log("✅ Apple ID Token Verified:", verifiedPayload);

      const appleId = verifiedPayload.sub; // Apple's unique user identifier
      let email = verifiedPayload.email || null; // Email may be missing

      console.log(`🍏 Received AppleID: ${appleId}, Email: ${email || "No email provided"}`);

      // Check if the user already exists in the database
      const checkQuery = `SELECT userId, email FROM users WHERE userId = ? OR email = ?`;
      db.query(checkQuery, [appleId, email], (err, results) => {
          if (err) {
              console.error("❌ Database error:", err);
              return res.status(500).json({ error: "Database error" });
          }

          if (results.length > 0) {
              // ✅ Existing user found
              const existingUser = results[0];
              console.log(`✅ Existing user found: userId=${existingUser.userId}, email=${existingUser.email || "No email"}`);

              // If email is missing, update it
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

              // Generate JWT for existing user
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
              // 🆕 New user - Insert into database
              console.log(`🆕 New user detected, inserting: ${email || "No email provided"}`);

              const insertQuery = `INSERT INTO users (userId, email) VALUES (?, ?)`;
              db.query(insertQuery, [appleId, email], (insertErr) => {
                  if (insertErr) {
                      console.error("❌ Error inserting new user:", insertErr);
                      return res.status(500).json({ error: "Failed to insert new user" });
                  }

                  console.log(`✅ New user inserted: AppleID=${appleId}, Email=${email || "No email"}`);

                  // Generate JWT for new user
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
const model = 'gemini-1.5-pro-002'; // or gemini-1.0-pro if you prefer

// Access the generative model
const generativeModel = vertexAI.getGenerativeModel({
    model: model,
    generation_config: {
        temperature: 0.2,  // Adjust temperature for creativity
        topP: 0.8,
        topK: 40,
        maxOutputTokens: 1024 // adjust as needed
    },
});



// Apple Callback Route


const corsOptions = {
  origin: [process.env.FRONTEND_URL, process.env.FRONTEND_URL2,
    'http://localhost:5173', 
    'http://192.168.1.*', // Allow local network IPs
    'http://localhost:5173/dashboard', 
    'https://www.meniven.com',
    'https://qg048c0c0wos4o40gos4k0kc.128.140.43.244.sslip.io',
    'https://singular-catfish-deciding.ngrok-free.app'] , // Replace with your frontend's origin
  credentials: true, // Allow cookies to be sent with requests
  origin: true, // Allow all origins (for development purposes)
  methods: ["GET", "POST", "PUT", "DELETE"], // Allow all standard methods
  allowedHeaders: ["Content-Type", "Authorization"], // Allow necessary headers
};



async function  insertProducts1(jsonData) {

  console.log('Insert products endpoint hit');

  // how to clean the jsonData from the special characters that are not part of json format

  // jsonData = jsonData.replace(/[^a-zA-Z0-9\s.,:;{}[\]"']/g, ''); // Remove special characters

// how to resolve this issue with jsonData not being a valid json format, and how to convert it to a valid json format

//   jsonData = jsonData.replace(/([a-zA-Z0-9]+):/g, '"$1":'); // Add quotes around keys


// resove this error with jsonData : SyntaxError: Unexpected token '`', "```json

 
jsonData = jsonData
  // strip ```json at the very start
  .replace(/^```json\s*/, '')
  // strip any trailing ```
  .replace(/\s*```$/, '')
  // now remove any remaining single backticks in the body
  .replace(/`/g, '');




  const products = JSON5.parse(jsonData); // Parse the JSON data

  console.log('Products received:', products);

  if (!Array.isArray(products)) {

    console.error('Invalid JSON format:', products);

    return;
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

    // Loop through each product
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

      // Ensure keywords is an array
      if (!Array.isArray(keywords)) {
        console.log('Keywords is not an array:', keywords);
        throw new Error('Keywords must be an array');
      }

      for (const keyword of keywords) {
        console.log('Processing keyword:', keyword);
        // Check if the keyword exists in the database
        const existingKeyword = await dbQuery(
          `SELECT keywordId FROM keywords WHERE keyword = ?`,
          [keyword]
        );

        let keywordId; // Initialize keywordId

        if (existingKeyword.length > 0) {
          // If the keyword exists, get its keywordId
          keywordId = existingKeyword[0].keywordId;
        } else {
          // If the keyword does not exist, insert it into the keywords table
          const newKeywordResult = await dbQuery(
            `INSERT INTO keywords (keyword) VALUES (?)`,
            [keyword]
          );
          keywordId = newKeywordResult.insertId;
        }

        // Insert the productId and keywordId into the productkeywords table
        await dbQuery(
          `INSERT INTO productkeywords (productId, keywordId) VALUES (?, ?)`,
          [productId, keywordId]
        );

        // write code

        

        // for every keyword inserted, get the keywordId and insert it into productkeywords table
      }
    }

    await dbQuery('COMMIT');

    console.log('All products and keywords inserted successfully!');



  } catch (err) {
    console.error('Error during product insertion:', err);

    await dbQuery('ROLLBACK');
    //res.status(500).json({ error: 'Failed to insert products and keywords' });
    console.error('Transaction rolled back due to error:', err);

  }
};




async function formatDataToJson(textData, image_url, saleEndDate, storeId) {


  console.log('🔍 Formatting text data into JSON...');

  console.log('Text sale end date and store Id:', saleEndDate, storeId); // Log the text data for debugging


  const geminiPrompt = 'Can you format the text data given, about product sale information in albanian language from this sales flyer data for each product' +
  ' Convert ë letter to e for all the keywords. Do not include conjunctions, articles words in Albanian language, in keywords.\n' +
   ' Do not include size info for keywords but only for description , and only words with more than 2 characters include as keywords, \n' + 
  
   ' Do not show euro and percetage symbols. The storeId is the number that starts with @ sign , if available, but  do not include the @ sign  \n' + 
   
    `Text Data: ${textData}` +

    `The image url is: ${image_url}` +

    `The sale_end_date is: ${saleEndDate}` +

    `The storeId is: ${storeId}` +
  
   
    'The response should be in the JSON format for each product as object in an array of objects: \n' +
    `[
  
      {
        "product_description": "",
        "old_price": "",
        "new_price": "",
        "discount_percentage": "",
        "sale_end_date": "YYYY-MM-DD",
        "storeId": 1,
        "userId": 1,
        "image_url": "",
        "keywords": ["keyword1", "keyword2"]
  }]` +
  ' Replace the placeholder data in the example with extracted and given data, if available. \n' ;

  


  try {
      const response = await generativeModel.generateContent(geminiPrompt);
      const text = response.response.candidates[0].content.parts[0].text;
      console.log('Raw Output:', text); // Log raw output to inspect

      await insertProducts1(text); // Call the insert function with the text data


      // try {
      //     const jsonObject = JSON.parse(text);
      //     return jsonObject;
      // } catch (parseError) {
      //     console.error('JSON Parsing Error:', parseError);
      //     console.error('Failed JSON Text:', text); // Log the failed JSON string
      //     return null; // Or throw an error if you prefer
      // }

      // respond with the text data to the client with res.json

      return text; // Return the formatted JSON data




  } catch (error) {
      console.error('Gemini API Error:', error);
      return null; // Or throw an error
  }
}


console.log('corsOptions:', corsOptions);

app.use(cors(corsOptions)); // Allow all origins, especially Vite's localhost:5173

app.use(cookieParser());
app.use(bodyParser.json());



import authRoutes from "./routes/authRoutes.js"; // Import authentication routes
app.use("/auth", authRoutes);


const verifyToken = (req, res, next) => {
  const token = req.cookies.jwt; // Assuming JWT is stored in 'jwt' cookie
  if (!token) {
    return res.status(403).send('A token is required for authentication');
  }

  try {
    // Verify the token and extract user data
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;  // Attach decoded token (user data) to the request
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


  //console.log("🔒 Checking session...");

  const token = req.cookies.jwt; // Get JWT from cookies

  if (!token) {
      return res.json({ isLoggedIn: false, userId: null });
  }

  try {
      const decoded = jwt.verify(token, process.env.TOKEN_SECRET); // Verify JWT

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
      res.clearCookie("jwt"); // Remove invalid JWT
      return res.json({ isLoggedIn: false, userId: null });
  }
});



app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));



  app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/" }), (req, res) => {
    console.log("Google OAuth Callback Triggered");

    console.log("Cookies received:", req.cookies); // Log cookies to debug

    const token = req.cookies.jwt; // Get JWT token from cookies

    if (!token) {
        console.error("⚠️ No JWT token found in cookies.");
        return res.status(400).json({ error: "JWT token is missing" });
    }

    try {
        // ✅ Fix: Use TOKEN_SECRET for verification
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


    console.log("Cookies received:", req.cookies); // Log all cookies

    // Successful authentication, redirect home.
    const token = req.cookies.jwt; // Get JWT token stored in cookies

    console.log("Token received:", token);

    const email = req.user.emails[0].value; // Extract email
    const googleId = req.user.id; // Extract Google ID
    const name = req.user.displayName; // Extract Full Name

    if (!token) {
        return res.status(400).json({ error: "JWT token is missing" });
    }

    console.log("Received Token:", token);
console.log("Decoded Token:", jwt.decode(token));

    try {
      const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
      console.log("Decoded Token:", decoded);
  } catch (err) {
      console.error("JWT Verification Error:", err.message);
  }

    try {

      console.log("JWT Secret Key:", process.env.TOKEN_SECRET);

        const decoded = jwt.verify(token, process.env.TOKEN_SECRET); // Verify JWT token
        const userId = decoded.userId;

        console.log("✅ Decoded Token:", decoded);

        console.log("User ID from JWT:", userId);

        const query = `UPDATE users SET email = ? WHERE userId = ?`;

        db.query(query, [email, userId], (err, result) => {
            if (err) {
                console.error("Error updating user email:", err);
                return res.status(500).json({ error: "Database error" });
            }

            res.redirect(`${process.env.FRONTEND_URL}?emailUpdated=true`); // Redirect to frontend
        });

    } catch (err) {

      console.error("❌ JWT Verification Error:", err.message);
        return res.status(401).json({ error: "Invalid token" });
    }
});



const SECRET_KEY = 'AAAA-BBBB-CCCC-DDDD-EEEE';

const upload = multer({ dest: 'uploads/' }); // Define upload middleware


// Single‐file extract‐text route
app.post('/extract-text', upload.single('image'), async (req, res) => {
  console.log('🔍 Extracting text from image…');

  // extract the saleEndDate from body of api call

  const { saleEndDate, storeId } = req.body;
  console.log('Sale End Date:', saleEndDate); // Log the saleEndDate for debugging
  console.log('Store ID:', storeId); // Log the storeId for debugging
  console.log('Image file:', req.file); // Log the uploaded file for debugging


  try {
    // 1️⃣ Validate
    if (!req.file) {
      console.error('❌ No image file provided.');
      return res.status(400).json({ message: 'No image file provided.' });
    }

    const imagePath = req.file.path;
    console.log(`🛣️  Local path: ${imagePath}`);

    // 2️⃣ Upload to Cloudinary
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

      // keep the original file name
      public_id: req.file.originalname.split('.')[0], // Remove file extension
      resource_type: 'image',
      overwrite: true, // Overwrite if exists


    });

    // return repose with the uploaded image url and the original file name is successfully uploaded


    console.log('✅ Image uploaded to Cloudinary:', uploadedImage.secure_url);

    // Send image to Google Vision API
    const [result] = await client.textDetection(uploadedImage.secure_url);
    const detections = result.textAnnotations;
    let extractedText = '';

    if (detections && detections.length > 0) {
      extractedText = detections[0].description;
    }


    console.log('🔍 Extracted text:', extractedText);
   

    const jsonText = await formatDataToJson(extractedText, uploadedImage.secure_url);


    console.log('🔍 Formated json data:', jsonText);
    
    // --- START: Simplified Gemini API Call (Moved Here) ---
    // try {
    //   const response = await generativeModel.generateContent({
    //     contents: [{ role: 'user', parts: [{ text: 'Just say hello.' }] }],
    //   });
    //   const geminiResponseText = response.response.candidates[0].content.parts[0].text;
    //   console.log('✅ Gemini API Response (in route):', geminiResponseText);
    //   res.json({
    //     imageUrl: uploadedImage.secure_url,
    //     text: extractedText,
    //     geminiResponse: geminiResponseText // Include Gemini response
    //   });
    // } catch (geminiError) {
    //   console.error('❌ Gemini API Error (in route):', geminiError);
    //   return res.status(500).json({ message: 'Failed to call Gemini API', error: geminiError.message });
    // }
    // --- END: Simplified Gemini API Call ---

    // Delete temporary uploaded file from server
    fs.unlinkSync(imagePath);

        // send one response with all three pieces
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

    // Prepare an array to hold media file details
    const mediaFiles = result.resources.map((resource) => ({
      public_id: resource.public_id,
      format: resource.format,
      secure_url: resource.secure_url,
      thumbnail_url: cloudinary.url(resource.public_id, {
        width: 100,    // Thumbnail width
        height: 100,   // Thumbnail height
        crop: 'thumb', // Thumbnail crop mode
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

// Middleware to check for JWT
function authenticateJWT(req, res, next) {
  const token = req.cookies.jwt; // Get token from cookies


  if (!token) {
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY); // Verify and decode the token
    req.user = decoded; // Add user info to request object
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

      const userId = Math.random().toString(36).substring(2); // Generate userId

      // ✅ Fix: Use TOKEN_SECRET for signing
      token = jwt.sign({ userId }, process.env.TOKEN_SECRET, { expiresIn: '7d' });

      console.log('Generated JWT:', token);

      // ✅ Store JWT in the database
      const query = `INSERT INTO users (userToken, jwt) VALUES (?, ?)`;
      db.query(query, [userId, token], (err) => {
          if (err) {
              console.error('❌ Error inserting new JWT into database:', err);
              return res.status(500).json({ message: 'Failed to initialize user.' });
          }

          // ✅ Set JWT cookie
          res.cookie('jwt', token, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production',
              //maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
              // set max age to 1 day for testing purposes
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
          res.clearCookie('jwt'); // Remove invalid JWT
          return res.status(401).json({ error: "Invalid token, please reinitialize." });
      }
  }
});



// Route to set JWT cookie for a new user or returning user without a token
app.get('/initialize2', (req, res) => {

  console.log('Initialize endpoint hit');


  let token = req.cookies.jwt;

  if (!token) {
    console.log('No JWT found in cookies. Generating a new token.');

    // Generate a new unique user ID
    const userId = Math.random().toString(36).substring(2);

    // Create a new JWT
    //token = generateJwtToken({ userId });

            // ✅ Fix: Use TOKEN_SECRET for signing
            token = jwt.sign({ userId }, process.env.TOKEN_SECRET, { expiresIn: '7d' });

            console.log('Generated JWT:', token);


    // Insert the new JWT into the database
    const query = `INSERT INTO users (userToken, jwt) VALUES (?, ?)`;
    db.query(query, [userId, token], (err) => {
      if (err) {
        console.error('Error inserting new JWT into database:', err);
        return res.status(500).json({ message: 'Failed to initialize user.' });
      }

      // Set the JWT cookie
      res.cookie('jwt', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      return res.json({ message: 'JWT set for new user', userId });
    });
  } else {
    // Check if the JWT exists in the database
    const query = `SELECT * FROM users WHERE jwt = ?`;
    db.query(query, [token], (err, results) => {
      if (err) {
        console.error('Error querying JWT from database:', err);
        return res.status(500).json({ message: 'Failed to verify user.' });
      }

      if (results.length > 0) {
        console.log('JWT found in database. Reusing token.');
        const { userToken } = jwt.verify(token, SECRET_KEY);

        // get the userId from results
        const userId = results[0].userId;

        return res.json({ message: 'User identified', userId, userToken });
      } else {
        console.log('JWT not found in database. Treating as a new user.');

        // If token isn't in the database, create a new one
        const userId = Math.random().toString(36).substring(2);
        token = generateJwtToken({ userId });

        const insertQuery = `INSERT INTO users (userId, jwt) VALUES (?, ?)`;
        db.query(insertQuery, [userId, token], (err) => {
          if (err) {
            console.error('Error inserting new JWT into database:', err);
            return res.status(500).json({ message: 'Failed to initialize user.' });
          }


          // Set the JWT cookie
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


// Route to save user preferences
app.post('/save-preferences', authenticateJWT, (req, res) => {
  const { userId } = req.user; // Get user ID from the JWT
  const { preferences } = req.body; // Get preferences from the request body

  // Save preferences in the mock database;
  // preferencesDB[userId] = preferences;

  // code to insers the uerId into the users table field jwt 

  
  
  // add code for api 




  res.json({ message: 'Preferences saved', userId, preferences });
});

// Route to get user preferences
app.get('/get-preferences', authenticateJWT, (req, res) => {
  const { userId } = req.user; // Get user ID from the JWT

  //const preferences = preferencesDB[userId] || {}; // Retrieve preferences or return empty object

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
    // Start a transaction
    await dbQuery('START TRANSACTION');

    // Delete product-keyword relations from ProductKeywords
    await dbQuery('DELETE FROM ProductKeywords WHERE productId = ?', [productId]);

    // Optionally, clean up keywords that are no longer linked to any products
    await dbQuery(`
      DELETE FROM keywords 
      WHERE keywordId NOT IN (SELECT keywordId FROM ProductKeywords)
    `);

    // Delete the product from the products table
    await dbQuery('DELETE FROM products WHERE productId = ?', [productId]);

    // Commit the transaction
    await dbQuery('COMMIT');
    
    res.status(200).json({ message: 'Product and related data deleted successfully.' });
  } catch (error) {
    // Rollback transaction in case of error
    await dbQuery('ROLLBACK');
    console.error('Error deleting product:', error);
    res.status(500).json({ message: 'An error occurred while deleting the product.' });
  }
});

app.post('/insertProducts', (req, res) => {
  // Extract the array of products from the request body
  const products = req.body;


  // Check if the data is an array
  if (Array.isArray(products)) {
    // Loop through each product in the array
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

    // Send a response back to the client
    res.status(200).json({ message: 'Products processed successfully' });
  } else {
    res.status(400).json({ message: 'Invalid data format. Expected an array of products.' });
  }
});


// POST endpoint to insert products



app.post('/insertProducts1', async (req, res) => {

  console.log('Insert products endpoint hit');

  const products = req.body;
  let responseSent = false;  // Track if the response has been sent

  console.log('Products received:', products);

  if (!Array.isArray(products)) {
    if (!responseSent) {
      res.status(400).json({ message: 'Invalid data format. Expected an array of products.' });
      responseSent = true;
    }
    return;
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

    // Loop through each product
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

      // Ensure keywords is an array
      if (!Array.isArray(keywords)) {
        console.log('Keywords is not an array:', keywords);
        throw new Error('Keywords must be an array');
      }

      for (const keyword of keywords) {
        const keywordResult = await dbQuery(
          `INSERT INTO keywords (keyword) VALUES (?) 
          ON DUPLICATE KEY UPDATE keywordId = LAST_INSERT_ID(keywordId)`,
          [keyword]
        );

        const keywordId = keywordResult.insertId;

        await dbQuery(
          `INSERT INTO productkeywords (productId, keywordId) VALUES (?, ?)`,
          [productId, keywordId]
        );
      }
    }

    await dbQuery('COMMIT');
    if (!responseSent) {
      res.status(200).json({ message: 'All products and keywords inserted successfully!' });
      responseSent = true;
    }

  } catch (err) {
    console.error('Error during product insertion:', err);
    if (!responseSent) {
      await dbQuery('ROLLBACK');
      res.status(500).json({ error: 'Failed to insert products and keywords' });
      responseSent = true;
    }
  }
});

// write api to get all stores from database table stores

// create a get endpoint that will extarct text from image using tesseract.js and return the extracted text as response GIVE THE IMAGE URL AS QUERY PARAMETER




// create a api endpoint to rename the image file in cloudinary with the public_id and new name as query parameters


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

  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
  const q = `SELECT * from stores order by storeId asc`;

  //console.log("getUserEmail:", q);

  const userId= req.query.userId;

    db.query(q, (err, data) => {

    if (err) {


      console.log("getStores error:", err);
      return res.json(err);
    }

    return res.json(data);
  });
});



// write api to check if product is already in favorites for a user

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
  }
  );
});


// write api to add a product to favorites for a user


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
  }
  );
});

// write api to remove a product from favorites for a user

app.delete("/removeFavorite", (req, res) => {

  const { userId, productId } = req.body;

  const q = `DELETE FROM favorites WHERE userId = ? AND productId = ?`;

  db.query(q, [userId, productId], (err, result) => {

    if (err) {

      console.error('Error removing favorite:', err);
      return res.status(500).json({ error: 'Failed to remove favorite' });
    }
    res.status(200).json({ message: 'Favorite removed successfully' });
  }
  );
});



app.get("/getUsers", (req, res) => {

  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
  const q = `SELECT * from users order by userId asc`;

  //console.log("getUserEmail:", q);

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

    // Create a condition for each keyword to be longer than 1 character 
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

// add api to add a keword to a product in the database table productkeywords and keywords

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
  }
  );
});

// add api to remove a keword from a product in the database table productkeywords and keywords



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
  }
  );

});


// add api to edit the product description for a product with product id and new description

app.put("/editProductDescription", (req, res) => {
  
  const { productId, newDescription } = req.body;

  const q = `UPDATE products SET product_description = ? WHERE productId = ?`;

  db.query(q, [newDescription, productId], (err, result) => {
    if (err) {
      console.error('Error updating product description:', err);
      return res.status(500).json({ error: 'Failed to update product description' });
    }
    res.status(200).json({ message: 'Product description updated successfully' });
  }
  );
}
);

app.put("/editProductSaleDate", (req, res) => {
  
  const { productId, sale_end_date } = req.body;

  console.log('Received sale_end_date:', sale_end_date);

  // convert date to mysql date type
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
  }
  );
}
);


app.put("/editStore", (req, res) => {
  
  const { productId, storeId } = req.body;

  const q = `UPDATE products SET storeId = ? WHERE productId = ?`;

  db.query(q, [storeId, productId], (err, result) => {
    if (err) {
      console.error('Error updating store :', err);
      return res.status(500).json({ error: 'Failed to update store' });
    }
    res.status(200).json({ message: 'Store updated successfully' });
  }
  );
}
);
//update getProducts endpoint to order the results by keyword count matches between the keywords of the favorite products and the keywords of the products in the database descending

app.get("/getProducts", async (req, res) => {



console.log('getProducts endpoint hit');

  const userId = parseInt(req.query.userId, 10) || null;
  let storeId = parseInt(req.query.storeId, 10);
  const isFavorite = req.query.isFavorite || null;
  const onSale = req.query.onSale || null;

  const keyword = req.query.keyword || null;  // Add the keyword parameter

  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 20) || 20;
  const offset = (page - 1) * limit;

  const today = new Date().toISOString().split('T')[0];

  // Handle invalid storeId case
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

  // Dynamically build the WHERE clause
  let conditions = [];
  if (storeId !== null) {
    conditions.push(`p.storeId = ?`);
    params.push(storeId);
  }

  //console.log('isFavorite::::::::::::', isFavorite);
  //console.log('isFavorite type:', typeof isFavorite);
  //console.log('isFavorite value:', isFavorite, 'Length:', isFavorite.length);


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

  // If there are conditions, add WHERE and concatenate the conditions
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

  // Add limit and offset to the params
  params.push(limit, offset);

  //console.log("Executing Query:", q);
  //console.log("With Params:", params);

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

  const keyword = req.query.keyword || null;  // Add the keyword parameter

  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const offset = (page - 1) * limit;

  const today = new Date().toISOString().split('T')[0];

  // Handle invalid storeId case
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

  // Dynamically build the WHERE clause
  let conditions = [];
  if (storeId !== null) {
    conditions.push(`p.storeId = ?`);
    params.push(storeId);
  }

  //console.log('isFavorite::::::::::::', isFavorite);
  //console.log('isFavorite type:', typeof isFavorite);
  //console.log('isFavorite value:', isFavorite, 'Length:', isFavorite.length);


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

  // If there are conditions, add WHERE and concatenate the conditions
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

  // Add limit and offset to the params
  params.push(limit, offset);

  //console.log("Executing Query:", q);
  //console.log("With Params:", params);

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
      // Delete image from Cloudinary
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
  


  //create a get endpoint that will take storeId and prompt string as query parameters and return the response from openai chat completions api

  app.get('/chatgptExtractProducts', async (req, res) => {

    const { storeId, imageUrl } = req.query;

    const imageBaseUrl = "https://res.cloudinary.com/dt7a4yl1x/image/upload/";

    // get image name as the last part of the URL split with forward slash /
    
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




    //console.log('response:', response.choices[0]);

    let resp = response.choices[0];

    let content = resp.message.content;

// Remove the code block markers (```json and ```)
content = content.replace(/```json\n/, '').replace(/```$/, '');

// Parse the remaining content as JSON
const productList = JSON.parse(content);

console.log(productList);




    res.json(productList);
  }
  );


  //write function to upload multiple images to cloudinary and return the public ids of the uploaded images , with all functionali os the upload endpoint


  app.post('/upload-multiple', upload.array('images', 10), async (req, res) => {

    const { folderName, storeId } = req.body; // Get folder name from request body

    console.log('folderName:', folderName);
    console.log('storeId:', storeId);

    try {
      const uploadPromises = req.files.map(async (file) => {

        const imagePath = file.path;

        const result = await cloudinary.uploader.upload(imagePath, {

          folder: folderName || 'default-folder', // If no folder is specified, use 'default-folder'
          use_filename: true,                       // Keep the original filename
          unique_filename: false,
        });

        console.log('result from upload:', result.public_id);

        const publicId = result.public_id;

        // split the public_id with forward slash / and get the last part of the string

        const imageName = publicId.split('/').pop();

        // can you add option to add text overlay at the bottom also

        const transformationResult = await cloudinary.uploader.upload(publicId, {
          type: 'upload',
          overwrite: true, // Ensure the image is replaced
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

        // add code to download the image from the transformed image url and save it to the local folder using cloudinary

        const options = {
          url: transformationResult.secure_url,
          dest: '../../downloads/',
        };

        download.image(options)


          .then(({ filename }) => {
            console.log('Saved to', filename);  // saved to /path/to/dest/image.jpg
          }
          )
          .catch((err) => console.error(err));

        // Clean up the local uploaded file
        fs.unlinkSync(imagePath);

        // Return the Cloudinary URL and public ID of the uploaded image
        return { success: true, url: result.secure_url, public_id: result.public_id, format: result.format };
      });

      const results = await Promise.all(uploadPromises);

      res.json(results);
    } catch (error) {
      res.status(500).json({ success: false, error: 'Failed to upload image' });
    }
  });

  


//upload.array('images', 10)




// Function to upload an image to a specific folder in Cloudinary
app.post('/upload', upload.array('images', 10), async (req, res) => {
  try {
    const uploadPromises = req.files.map(async (file) => {
      const imagePath = file.path;
      //const imagePath = req.file.path;
      const { folderName } = req.body; // Get folder name from request body

      console.log('folderName:', folderName);

      const result = await cloudinary.uploader.upload(imagePath, {
        folder: folderName || 'default-folder', // If no folder is specified, use 'default-folder'
        use_filename: true,                       // Keep the original filename
        unique_filename: false,
      });

      console.log('result from upload:', result.public_id);

      const publicId = result.public_id;
      // split the public_id with forward slash / and get the last part of the string
      const imageName = publicId.split('/').pop();

      // can you add option to add text overlay at the bottom also

      const transformationResult = await cloudinary.uploader.upload(result.secure_url, {
        type: 'upload',
        overwrite: true, // Ensure the image is replaced
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

      // add code to download the image from the transformed image url and save it to the local folder using cloudinary

      const options = {
        url: transformationResult.secure_url,
        dest: '../../Downloads/',
      };

      download.image(options)
        .then(({ filename }) => {
          console.log('Saved to', filename);  // saved to /path/to/dest/image.jpg
        })
        .catch((err) => console.error(err));

      // can you add a way to save images locally using cloudinary

      // can you add a way to save images locally using cloudinary

      const saveLocally = async (url, destination) => {
        try {
          const opts = { url, dest: destination };
          const { filename } = await download.image(opts);
          console.log('Saved to locally:', filename);
        } catch (error) {
          console.error(error);
        }
      };

      // Usage:
      const transformedImageUrl = transformationResult.secure_url;
      const localDestination = '../../Downloads/';
      await saveLocally(transformedImageUrl, localDestination);

      // Clean up the local uploaded file
      fs.unlinkSync(imagePath);

      // Return the Cloudinary URL and public ID of the uploaded image
      return {
        success: true,
        url: result.secure_url,
        public_id: result.public_id,
        format: result.format
      };
    });

    // Wait for all uploads/transforms/downloads to finish
    const images = await Promise.all(uploadPromises);

    // Send a single response with all results
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