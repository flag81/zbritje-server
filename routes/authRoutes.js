import express from "express";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import db from '../connection.js';

console.log("🔍 Checking Email Credentials:");
console.log("📧 EMAIL_USER:", process.env.EMAIL_USER ? "Loaded" : "❌ Not Found");
console.log("🔑 EMAIL_PASS:", process.env.EMAIL_PASS ? "Loaded" : "❌ Not Found");

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

const router = express.Router();

router.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "http://localhost:5173");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.header("Access-Control-Allow-Credentials", "true");
    next();
});



const verificationCodes = {}; // Temporary store for verification codes

// ✅ 1. Send Verification Code to Email
router.post("/send-verification-code", (req, res) => {
    console.log("📧 Received request body:", req.body);  // ✅ Debugging log

    if (!req.body || !req.body.email) {
        console.error("❌ ERROR: `email` is missing in request body!");
        return res.status(400).json({ success: false, message: "Email is required" });
    }

    const { email } = req.body;
    const code = Math.floor(100000 + Math.random() * 900000); // Generate 6-digit code

    verificationCodes[email] = code;
    console.log(`✅ Verification code for ${email}: ${code}`);

    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your Verification Code",
        text: `Your verification code is: ${code}`,
    };

    transporter.sendMail(mailOptions, (error) => {
        if (error) {
            console.error("❌ Email error:", error);
            return res.status(500).json({ success: false, message: "Failed to send email" });
        }
        res.json({ success: true, message: "Verification code sent" });
    });
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

                return res.json({ success: true, userId, email: email });
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
