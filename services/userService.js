import jwt from 'jsonwebtoken';
import { queryPromise } from '../dbUtils.js';
import db from '../connection.js';
import logger from './logger.js';

export async function ensureAnonUserRow({ tokenUserId, reqId, caller }) {
  if (typeof tokenUserId !== 'string' || !tokenUserId.startsWith('anon_')) return null;

  const lockName = `users.userId:${tokenUserId}`.slice(0, 64);
  let gotLock = false;

  const parseGotLock = (rows) => {
    if (!Array.isArray(rows) || rows.length === 0) return false;
    const row = rows[0] || {};
    const value = row.gotLock ?? row.GOT_LOCK ?? Object.values(row)[0];
    return value === 1 || value === '1' || value === true;
  };

  try {
    try {
      const lockRows = await queryPromise('SELECT GET_LOCK(?, 2) AS gotLock', [lockName]);
      gotLock = parseGotLock(lockRows);
      if (!gotLock) {
        logger.warn(`[${caller}] (${reqId}) could not obtain GET_LOCK for ${tokenUserId}; continuing without lock`);
      }
    } catch (e) {
      logger.warn(`[${caller}] (${reqId}) GET_LOCK failed; continuing without lock: ${e.message}`);
    }

    const existing = await queryPromise('SELECT id FROM users WHERE userId = ? ORDER BY id DESC LIMIT 1', [
      tokenUserId,
    ]);
    if (Array.isArray(existing) && existing[0]?.id) return existing[0].id;

    await queryPromise(
      `INSERT INTO users (userId, is_registered, timestamp)
       SELECT ?, ?, NOW()
       FROM DUAL
       WHERE NOT EXISTS (SELECT 1 FROM users WHERE userId = ? LIMIT 1)`,
      [tokenUserId, false, tokenUserId],
    );

    const repaired = await queryPromise('SELECT id FROM users WHERE userId = ? ORDER BY id DESC LIMIT 1', [
      tokenUserId,
    ]);
    return Array.isArray(repaired) && repaired[0]?.id ? repaired[0].id : null;
  } finally {
    if (gotLock) {
      try {
        await queryPromise('SELECT RELEASE_LOCK(?)', [lockName]);
      } catch {}
    }
  }
}

export async function handleInitialize(req, res) {
  const reqId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

  const buildJwtCookieOptions = () => {
    const forwardedProto = req.headers['x-forwarded-proto'];
    const isHttps = Boolean(req.secure) || (typeof forwardedProto === 'string' && forwardedProto.includes('https'));
    const host = (req.headers.host || '').split(':')[0];
    const isMenivenDomain = host.endsWith('meniven.com');
    return {
      httpOnly: true,
      secure: isHttps,
      sameSite: isHttps ? 'None' : 'Lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
      ...(isMenivenDomain ? { domain: '.meniven.com' } : {}),
    };
  };

  if (req.identifiedUser && req.identifiedUser.userId) {
    const tokenUserId = req.identifiedUser.userId;
    try {
      if (typeof tokenUserId === 'string' && tokenUserId.startsWith('anon_')) {
        await ensureAnonUserRow({ tokenUserId, reqId, caller: 'initialize' });
      }
    } catch (e) {
      logger.error(`[initialize] (${reqId}) failed to ensure user exists:`, e);
    }

    const headerToken = req.headers.authorization?.startsWith('Bearer ')
      ? req.headers.authorization.split(' ')[1]
      : null;
    const cookieToken = req.cookies?.jwt || null;
    const token = headerToken || cookieToken;
    if (token && !cookieToken) {
      res.cookie('jwt', token, buildJwtCookieOptions());
      res.setHeader('Meniven-Init-Cookie', '1');
    }
    return res.json({
      message: 'User identified',
      userId: tokenUserId,
      token,
      cookieAttempted: Boolean(token) && !Boolean(cookieToken),
    });
  }

  if (!process.env.TOKEN_SECRET) {
    return res.status(500).json({ message: 'Server misconfigured: TOKEN_SECRET missing.' });
  }

  const anonymousUserId = `anon_${Date.now()}`;
  const tokenPayload = { userId: anonymousUserId };
  const token = jwt.sign(tokenPayload, process.env.TOKEN_SECRET, { expiresIn: '30d' });

  try {
    await ensureAnonUserRow({ tokenUserId: anonymousUserId, reqId, caller: 'initialize' });
    res.cookie('jwt', token, buildJwtCookieOptions());
    res.setHeader('Meniven-Init-Cookie', '1');
    return res.json({ message: 'Anonymous user initialized', userId: anonymousUserId, token, cookieAttempted: true });
  } catch (err) {
    logger.error(`[initialize] (${reqId}) failed to insert anonymous user:`, err);
    return res.status(500).json({ message: 'Failed to initialize anonymous user.' });
  }
}
