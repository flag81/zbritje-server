import jwt from 'jsonwebtoken';
import { queryPromise } from '../dbUtils.js';

/**
 * POST /auth/login - For dashboard users
 * Authenticates a user with username and password.
 */
export const dashboardLogin = async (req, res) => {
    const { username, password } = req.body;
    try {
        const q = 'SELECT id, first_name, last_name, email, is_registered FROM users WHERE first_name = ? AND password = ?';
        const [user] = await queryPromise(q, [username, password]);

        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const tokenPayload = { id: user.id, email: user.email };
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('jwt', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.json({ message: 'Login successful', user });
    } catch (error) {
        console.error('[Login Error]', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
};

/**
 * GET /auth/initialize - For mobile app
 * Initializes a session for a user. If no valid token is found, creates a new anonymous user.
 */
export const initializeSession = async (req, res) => {
    if (req.identifiedUser && req.identifiedUser.id) {
        console.log(`✅ [Auth] User already identified: ${req.identifiedUser.id}`);
        const token = req.headers.authorization?.split(' ')[1] || req.cookies.jwt;
        return res.json({ message: 'User identified', userId: req.identifiedUser.id, token });
    }

    console.log('⚠️ [Auth] No valid user. Generating new anonymous user.');
    try {
        const insertResult = await queryPromise('INSERT INTO users (is_registered) VALUES (false)');
        const newUserId = insertResult.insertId;

        const tokenPayload = { id: newUserId };
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '2y' });

        res.cookie('jwt', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax',
            maxAge: 2 * 365 * 24 * 60 * 60 * 1000,
        });

        res.json({ message: 'Anonymous user initialized', userId: newUserId, token });
    } catch (error) {
        console.error('[Initialize Error]', error);
        res.status(500).json({ message: 'Failed to initialize anonymous user.' });
    }
};

/**
 * GET /auth/check-session
 * Checks if the current user has a valid session token.
 */
export const checkSession = async (req, res) => {
    if (!req.identifiedUser || !req.identifiedUser.id) {
        return res.json({ isLoggedIn: false, userId: null });
    }

    try {
        const q = 'SELECT id, email, first_name, is_registered FROM users WHERE id = ?';
        const [user] = await queryPromise(q, [req.identifiedUser.id]);

        if (!user) {
            res.clearCookie('jwt');
            return res.json({ isLoggedIn: false, userId: null });
        }

        res.json({
            isLoggedIn: true,
            isRegistered: !!user.is_registered,
            userId: user.id,
            email: user.email,
            firstName: user.first_name,
        });
    } catch (error) {
        console.error('[Check Session Error]', error);
        res.status(500).json({ isLoggedIn: false, userId: null });
    }
};

/**
 * GET /auth/logout
 * Clears the session cookie.
 */
export const logout = (req, res) => {
    res.clearCookie('jwt', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Lax',
    });
    res.json({ success: true, message: 'Logged out successfully.' });
};