import jwt from 'jsonwebtoken';
import { queryPromise } from '../dbUtils.js';
import db from '../connection.js';
import AppleSigninAuth from 'apple-signin-auth';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { handleInitialize, ensureAnonUserRow } from '../services/userService.js';
import logger from '../services/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const privateKeyPath = path.join(__dirname, '../persistent/keys/AuthKey_6YK9NFRYH9.p8');
let privateKey;
try {
  privateKey = fs.readFileSync(privateKeyPath, 'utf8');
} catch (e) {
  logger.error('Apple private key not found:', privateKeyPath);
}

const generateAppleClientSecret = () => {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    {
      iss: process.env.APPLE_TEAM_ID,
      iat: now,
      exp: now + 15777000,
      aud: 'https://appleid.apple.com',
      sub: process.env.APPLE_CLIENT_ID,
    },
    privateKey,
    { algorithm: 'ES256', keyid: process.env.APPLE_KEY_ID },
  );
};

export const appleSignIn = async (req, res) => {
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
    logger.error(error);
    res.status(500).json({ error: 'Apple Sign-in failed' });
  }
};

export const appleCallback = async (req, res) => {
  try {
    const { code, id_token } = req.body;
    if (!code && !id_token) return res.status(400).json({ error: 'Missing Apple authorization data' });

    let decodedToken;
    if (id_token) {
      decodedToken = jwt.decode(id_token);
    } else {
      const clientSecret = generateAppleClientSecret();
      const axios = (await import('axios')).default;
      const appleResponse = await axios.post('https://appleid.apple.com/auth/token', null, {
        params: {
          client_id: process.env.APPLE_CLIENT_ID,
          client_secret: clientSecret,
          code: code,
          grant_type: 'authorization_code',
          redirect_uri: process.env.APPLE_CALLBACK_URL,
        },
      });
      if (!appleResponse.data.id_token) return res.status(400).json({ error: 'Failed to authenticate with Apple' });
      decodedToken = jwt.decode(appleResponse.data.id_token);
    }

    if (!decodedToken) return res.status(400).json({ error: 'Invalid Apple ID token' });

    const appleId = decodedToken.sub;
    let email = decodedToken.email || null;

    const existsQuery = 'SELECT userId, email FROM users WHERE userId = ? OR email = ?';
    db.query(existsQuery, [appleId, email], (err, results) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (results.length > 0) {
        const existingUser = results[0];
        if (!existingUser.email && email) {
          db.query('UPDATE users SET email = ? WHERE userId = ?', [email, existingUser.userId]);
        }
        const token = jwt.sign(
          { userId: existingUser.userId, email: existingUser.email || email },
          process.env.TOKEN_SECRET,
          { expiresIn: '7d' },
        );
        res.cookie('jwt', token, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 7 * 24 * 60 * 60 * 1000 });
        return res.redirect(`${process.env.FRONTEND_URL}?loginSuccess=true`);
      } else {
        const insertQuery = `INSERT INTO users (first_name, email) VALUES (?, ?)`;
        db.query(insertQuery, [appleId, email], (insertErr) => {
          if (insertErr) return res.status(500).json({ error: 'Failed to insert new user' });
          const token = jwt.sign({ userId: appleId, email }, process.env.TOKEN_SECRET, { expiresIn: '7d' });
          res.cookie('jwt', token, { httpOnly: true, secure: true, sameSite: 'None', maxAge: 7 * 24 * 60 * 60 * 1000 });
          return res.redirect(`${process.env.FRONTEND_URL}?loginSuccess=true`);
        });
      }
    });
  } catch (error) {
    logger.error('Apple OAuth Error:', error);
    return res.status(500).json({ error: 'Apple authentication failed' });
  }
};

export const googleCallback = (req, res) => {
  const token = req.cookies.jwt;
  if (!token) return res.status(400).json({ error: 'JWT token is missing' });
  try {
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
    const userId = decoded.userId;
    const email = req.user.emails[0].value;
    const query = `UPDATE users SET email = ? WHERE userId = ?`;
    db.query(query, [email, userId], (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.redirect(`${process.env.FRONTEND_URL}?emailUpdated=true`);
    });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

export { handleInitialize };

export const checkSession = async (req, res) => {
  const reqId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

  const hasAuthHeader = Boolean(req.headers.authorization && req.headers.authorization.startsWith('Bearer '));
  const hasJwtCookie = Boolean(req.cookies && req.cookies.jwt);
  const authSource = hasAuthHeader ? 'header' : hasJwtCookie ? 'cookie' : 'none';

  const tokenUserId = req.identifiedUser?.userId ?? null;
  const numericId =
    req.identifiedUser?.id ??
    (typeof tokenUserId === 'string' && /^\d+$/.test(tokenUserId) ? parseInt(tokenUserId, 10) : null);

  if (!tokenUserId && !numericId) {
    return res.json({
      isLoggedIn: false,
      isRegistered: false,
      userId: null,
      email: null,
      shouldReinitialize: false,
      reason: 'NO_TOKEN',
    });
  }

  try {
    const q = numericId
      ? `SELECT id, email, first_name, is_registered FROM users WHERE id = ? LIMIT 1`
      : `SELECT id, email, first_name, is_registered FROM users WHERE userId = ? ORDER BY id DESC LIMIT 1`;

    const results = await queryPromise(q, [numericId ?? tokenUserId]);

    if (!results || results.length === 0) {
      if (!numericId && typeof tokenUserId === 'string' && tokenUserId.startsWith('anon_')) {
        try {
          const repairedId = await ensureAnonUserRow({ tokenUserId, reqId, caller: 'check-session' });
          if (repairedId) {
            const repaired = await queryPromise(
              'SELECT id, email, first_name, is_registered FROM users WHERE id = ? LIMIT 1',
              [repairedId],
            );
            if (Array.isArray(repaired) && repaired.length > 0) {
              const user = repaired[0];
              return res.json({
                isLoggedIn: true,
                isRegistered: !!user.is_registered,
                userId: user.id,
                email: user.email ?? null,
                shouldReinitialize: false,
                reason: null,
                authSource,
              });
            }
          }
        } catch (e) {
          logger.error(`[check-session] failed to self-heal anon user:`, e);
        }
      }

      if (authSource === 'cookie') res.clearCookie('jwt');
      return res.json({
        isLoggedIn: false,
        isRegistered: false,
        userId: null,
        email: null,
        shouldReinitialize: true,
        reason: 'USER_NOT_FOUND',
        authSource,
      });
    }

    const user = results[0];
    return res.json({
      isLoggedIn: true,
      isRegistered: !!user.is_registered,
      userId: user.id,
      email: user.email ?? null,
      shouldReinitialize: false,
      reason: null,
      authSource,
    });
  } catch (err) {
    logger.error('DB error during /check-session:', err);
    return res.status(500).json({
      isLoggedIn: false,
      isRegistered: false,
      userId: null,
      email: null,
      shouldReinitialize: false,
      reason: 'DB_ERROR',
      authSource,
    });
  }
};

export const dashboardLogin = async (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM users WHERE first_name = ? AND last_name = ?';
  db.query(query, [username, password], (err, results) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    if (results.length > 0) {
      const user = results[0];
      res.json({ user: { userId: user.userId, userName: user.userName } });
    } else {
      res.status(401).json({ message: 'Invalid username or password' });
    }
  });
};

export const initializeAnonymous = async (req, res) => {
  try {
    const [result] = await db.promise().query('INSERT INTO users () VALUES ()');
    const userId = result.insertId;
    if (!userId) return res.status(500).json({ message: 'Failed to create anonymous user.' });
    const token = jwt.sign({ userId }, process.env.TOKEN_SECRET, { expiresIn: '2y' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error during initialization.' });
  }
};

export const getUserPreferences = async (req, res) => {
  if (!req.identifiedUser?.userId) return res.status(401).json({ error: 'User identification required.' });
  try {
    const q = 'SELECT first_name, last_name, email, notification_frequency FROM users WHERE id = ?';
    const [user] = await queryPromise(q, [req.identifiedUser.userId]);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email,
      notificationFrequency: user.notification_frequency,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get preferences.' });
  }
};

export const updateUserPreferences = async (req, res) => {
  if (!req.identifiedUser?.userId) return res.status(401).json({ error: 'User identification required.' });
  const { notificationFrequency } = req.body;
  const validFrequencies = ['daily', 'weekly', 'monthly', 'off'];
  if (!validFrequencies.includes(notificationFrequency))
    return res.status(400).json({ error: 'Invalid notification frequency value.' });
  try {
    const q = 'UPDATE users SET notification_frequency = ? WHERE id = ?';
    await queryPromise(q, [notificationFrequency, req.identifiedUser.userId]);
    res.json({ message: 'Preferences updated successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update preferences.' });
  }
};

export const getUsers = (req, res) => {
  const q = `SELECT * from users order by userId asc`;
  db.query(q, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
};
