import express from "express";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import db from '../connection.js';

console.log("🔍 Checking Email Credentials:");
console.log("📧 EMAIL_USER:", process.env.EMAIL_USER ? "Loaded" : "❌ Not Found");
console.log("🔑 EMAIL_PASS:", process.env.EMAIL_PASS ? "Loaded" : "❌ Not Found");

console.log(process.env.EMAIL_USER, process.env.EMAIL_PASS);
console.log("🔍 Checking SMTP connection...----.....-----......");






;


const router = express.Router();

//FRONTEND_URL 

router.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", process.env.FRONTEND_URL);
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.header("Access-Control-Allow-Credentials", "true");
    next();
});



const verificationCodes = {}; // Temporary store for verification codes

// ✅ 1. Send Verification Code to Email


router.post("/send-verification-code", async (req, res) => {
    try {
        console.log("📧 Received request body:", req.body); // Debugging log

        // Validate request body
        if (!req.body || !req.body.email) {
            console.error("❌ ERROR: `email` is missing in request body!");
            return res.status(400).json({ success: false, message: "Email is required" });
        }

        const { email } = req.body;

        // Generate a 6-digit verification code
        const code = Math.floor(100000 + Math.random() * 900000);
        verificationCodes[email] = code;
        console.log(`✅ Verification code for ${email}: ${code}`);

        // Check if environment variables are set
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
            console.error("❌ ERROR: Missing email credentials in environment variables!");
            return res.status(500).json({ success: false, message: "Email service is not configured properly" });
        }
        else {

            console.log("✅ Email credentials are set.", {
                EMAIL_USER: process.env.EMAIL_USER,
                EMAIL_PASS: process.env.EMAIL_PASS ? "Loaded" : "Not Loaded",
            });
        }



        const transporter = nodemailer.createTransport({
            service: 'gmail',
            host: 'smtp.gmail.com',
            port: 587,
            secure: false,         // use STARTTLS instead of SSL
            requireTLS: true,      // upgrade to TLS
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            }
        },{ debug: true, logger: true });

        transporter.verify((error, success) => {

            console.log("🔍 Verifying SMTP connection...++++++++");

            if (error) {
              console.error("SMTP connection error:", error);
            } else {
              console.log("SMTP server is ready to take messages:", success);
            }
          });

        // Define email options
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your Verification Code",
            text: `Your verification code is: ${code}`,
        };

        console.log("📧 mailOptions:", mailOptions); // Debugging log

        // Send the email

    await new Promise((resolve, reject) => {
        transporter.sendMail(mailOptions, (error, info) => {

            console.log("📧 Sending email to:", email); // Debugging log

            if (error) {
                console.error("❌ Email error:", error);
                //return res.status(500).json({ success: false, message: "Failed to send email" });
                return reject(err);
            }
            console.log("✅ Email sent successfully");
            //resolve(info);
            resolve(info);
            //res.json({ success: true, message: "Verification code sent successfully." });
        });

    });

    console.log("✅ Email sent:");
    return res.json({ success: true, message: "Verification code sent successfully." });


    } catch (err) {
        // Catch any unexpected errors
        console.error("❌ ERROR: Unexpected error occurred:", err);
        res.status(500).json({ success: false, message: "An unexpected error occurred" });
    }
});


router.post("/send-verification-code222", async (req, res) => {
    try {
      // … validate + prepare mailOptions …
  
      const info = await new Promise((resolve, reject) => {
        transporter.sendMail(mailOptions, (err, info) => {
          if (err) {
            console.error("❌ sendMail callback error:", err);
            return reject(err);
          }
          resolve(info);
        });
      });
  
      console.log("✅ Email sent:", info.messageId);
      return res.json({ success: true, message: "Verification code sent successfully." });
    }
    catch (err) {
      console.error("❌ sendMail promise wrapper error:", err);
      return res.status(500).json({ success: false, message: "Failed to send email", error: err.message });
    }
  });



router.post("/verify-code", (req, res) => {
    console.log("📧 Verifying code for:", req.body);

    //console.log("📧 verification Codes:", verificationCodes[email] );  // ✅ Debugging log
    console.log("🔍 Stored Verification Codes:", verificationCodes); // ✅ Debug log


    const { email, code } = req.body;

    console.log("📧 email:", email );  // ✅ Debugging log


    console.log("📧 verification Codes from:", verificationCodes[email]?.toString() );  // ✅ Debugging log

    if (!email || !code) {
        console.error("❌ ERROR: Missing email or verification code");
        return res.status(400).json({ success: false, message: "Email and code are required" });
    }

    console.log("📧 verification Codes:", verificationCodes[email] );  // ✅ Debugging log

    if (!verificationCodes[email]?.toString() || verificationCodes[email]?.toString() !== code) {

            console.log("📧 verification Codes:", verificationCodes[email]?.toString() );  // ✅ Debugging log
            console.log("📧 verification Codes:", verificationCodes[email]?.toString() !== code );  // ✅ Debugging log

        console.error("❌ Invalid verification code attempt:", email);
        return res.status(400).json({ success: false, message: "Invalid code" });
    }

    // Remove the verification code from temporary storage
    delete verificationCodes[email];

    console.log(`✅ Verification successful for ${email}`);

    // Check if user exists
    const checkUserQuery = `SELECT userId FROM users WHERE email = ?`;
    db.query(checkUserQuery, [email], (err, results) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ success: false, message: "Database error" });
        }

        let userId;
        if (results.length > 0) {
            userId = results[0].userId;
            console.log(`✅ Existing user found: userId=${userId}`);

            // Generate JWT and return response
            const token = jwt.sign({ userId, email }, process.env.TOKEN_SECRET, { expiresIn: "7d" });
            res.cookie("jwt", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                maxAge: 7 * 24 * 60 * 60 * 1000,
            });
            return res.json({ success: true, userId });
        } else {
            // Insert new user
            console.log(`🆕 New user detected, inserting into database: ${email}`);
            const insertQuery = `INSERT INTO users (email, userName) VALUES (?, ?)`;
            db.query(insertQuery, [email, email], (insertErr, result) => {
                if (insertErr) {
                    console.error("❌ Error inserting new user:", insertErr);
                    return res.status(500).json({ success: false, message: "Database error" });
                }
                userId = result.insertId;
                console.log(`✅ New user inserted successfully with userId=${userId}`);

                // Generate JWT and return response
                const token = jwt.sign({ userId, email }, process.env.TOKEN_SECRET, { expiresIn: "7d" });
                res.cookie("jwt", token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production",
                    maxAge: 7 * 24 * 60 * 60 * 1000,
                });

                return res.json({ success: true, userId });
            });
        }
    });
});





router.get("/check-session", (req, res) => {
    const token = req.cookies.jwt;

    console.log("🍪 Checking session token:", token);

    if (!token) {
        return res.json({ userId: null, loggedIn: false });
    }

    try {
        const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
        const userId = decoded.userId;

        console.log("✅ Session token decoded:", decoded);

        // ✅ Fetch user details from database
        const query = `SELECT userId, email, googleId FROM users WHERE userId = ?`;
        db.query(query, [userId], (err, results) => {
            if (err) {
                console.error("❌ Error retrieving user from DB:", err);
                return res.status(500).json({ userId: null, loggedIn: false });
            }

            if (results.length === 0) {
                console.warn("⚠️ User not found in database. Clearing session.");
                res.clearCookie("jwt");
                return res.json({ userId: null, loggedIn: false });
            }

            // ✅ User is logged in
            res.json({
                userId: results[0].userId,
                email: results[0].email,
                loginMethod: results[0].googleId ? "Google" : "Email",
                loggedIn: true,
            });
        });

    } catch (error) {
        console.error("❌ Invalid session token:", error.message);
        res.clearCookie("jwt");
        return res.json({ userId: null, loggedIn: false });
    }
});

// ✅ 3. Check User Session
router.get("/check-session2", (req, res) => {
    const token = req.cookies.jwt;

    if (!token) {
        return res.json({ userId: null, loggedIn: false });
    }

    try {
        const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
        const userId = decoded.userId;

        // ✅ Fetch user details from database
        const query = `SELECT userId, email, googleId FROM users WHERE userId = ?`;
        db.query(query, [userId], (err, results) => {
            if (err) {
                console.error("❌ Error retrieving user from DB:", err);
                return res.status(500).json({ userId: null, loggedIn: false });
            }

            if (results.length === 0) {
                console.warn("⚠️ User not found in database. Clearing session.");
                res.clearCookie("jwt");
                return res.json({ userId: null, loggedIn: false });
            }

            // ✅ User is logged in
            res.json({
                userId: results[0].userId,
                email: results[0].email,
                loginMethod: results[0].googleId ? "Google" : "Email",
                loggedIn: true,
            });
        });

    } catch (error) {
        console.error("❌ Invalid session token:", error.message);
        res.clearCookie("jwt");
        return res.json({ userId: null, loggedIn: false });
    }
});


router.get("/logout", (req, res) => {
    res.clearCookie("jwt", {
        httpOnly: true,
        sameSite: "Lax",
    });
    res.json({ success: true, message: "Logged out and session cleared." });
});


export default router;
