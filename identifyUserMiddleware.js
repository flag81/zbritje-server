import jwt from 'jsonwebtoken';
import { queryPromise } from './dbUtils.js';

const identifyUserMiddleware = async (req, res, next) => {
  const reqTag = `${req.method} ${req.originalUrl}`;
  let token = null;
  let source = 'none';

  // 1. Check for token in Authorization header (for mobile app)
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
    source = 'header';
    console.log(`[Middleware] (${reqTag}) Found token in Authorization header.`);
  } 
  // 2. If not in header, check for token in cookies (for web app)
  else if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt;
    source = 'cookie';
    console.log(`[Middleware] (${reqTag}) Found token in cookies.`);
  }

  if (token) {
    try {
      if (!process.env.TOKEN_SECRET) {
        console.error('[Middleware] TOKEN_SECRET is not set. Cannot verify token.');
        req.identifiedUser = null;
        return next();
      }
      const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
      const tokenUserId = decoded.userId;

      console.log(`[Middleware] (${reqTag}) Decoded token userId=${tokenUserId}`);

      // Attach token user identifier to the request object.
      // NOTE: tokenUserId may be a numeric DB id OR a string like "anon_...".
      const identifiedUser = { userId: tokenUserId };

      // Best-effort: resolve numeric `users.id` so API endpoints can use a consistent key.
      try {
        if (typeof tokenUserId === 'number' && Number.isFinite(tokenUserId)) {
          identifiedUser.id = tokenUserId;
          console.log(`[Middleware] (${reqTag}) Using numeric token userId as db id: ${identifiedUser.id}`);
        } else if (typeof tokenUserId === 'string') {
          // If the token value is numeric-like, treat it as an id.
          if (/^\d+$/.test(tokenUserId)) {
            identifiedUser.id = parseInt(tokenUserId, 10);
            console.log(`[Middleware] (${reqTag}) Parsed numeric-like token userId to db id: ${identifiedUser.id}`);
          } else {
            // Otherwise, look up the user by the public userId (e.g. anon_...)
            const rows = await queryPromise(
              'SELECT id FROM users WHERE userId = ? ORDER BY id DESC LIMIT 1',
              [tokenUserId]
            );
            if (Array.isArray(rows) && rows.length > 0 && rows[0]?.id) {
              identifiedUser.id = rows[0].id;
              console.log(`[Middleware] (${reqTag}) Resolved db id ${identifiedUser.id} for token userId ${tokenUserId}`);
            } else {
              console.warn(`[Middleware] (${reqTag}) No DB row found for token userId ${tokenUserId}`);
            }
          }
        }
      } catch (lookupErr) {
        // Don't block the request if DB lookup fails; keep token-based identity.
        console.warn(`[Middleware] Failed to resolve DB user id for token userId '${tokenUserId}': ${lookupErr.message}`);
      }

      req.identifiedUser = identifiedUser;
      console.log(`[Middleware] (${reqTag}) User identified via ${source}: ${tokenUserId} (db id: ${identifiedUser.id ?? 'n/a'})`);
    } catch (err) {
      // Token is invalid or expired
      req.identifiedUser = null;
      console.warn(`[Middleware] (${reqTag}) Invalid token from ${source}. Error: ${err.message}`);
    }
  } else {
    // No token found
    req.identifiedUser = null;
    console.log(`[Middleware] (${reqTag}) No token found in request.`);
  }

  next();
};

export default identifyUserMiddleware;