import jwt from 'jsonwebtoken';

const identifyUserMiddleware = (req, res, next) => {
  let token = null;
  let source = 'none';

  // 1. Check for token in Authorization header (for mobile app)
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
    source = 'header';
    console.log('[Middleware] Found token in Authorization header.');
  } 
  // 2. If not in header, check for token in cookies (for web app)
  else if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt;
    source = 'cookie';
    console.log('[Middleware] Found token in cookies.');
  }

  if (token) {
    try {
      if (!process.env.TOKEN_SECRET) {
        console.error('[Middleware] TOKEN_SECRET is not set. Cannot verify token.');
        req.identifiedUser = null;
        return next();
      }
      const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
      // Attach user info to the request object
      req.identifiedUser = { userId: decoded.userId };
      console.log(`[Middleware] User identified via ${source}: ${decoded.userId}`);
    } catch (err) {
      // Token is invalid or expired
      req.identifiedUser = null;
      console.warn(`[Middleware] Invalid token from ${source}. Error: ${err.message}`);
    }
  } else {
    // No token found
    req.identifiedUser = null;
    console.log('[Middleware] No token found in request.');
  }

  next();
};

export default identifyUserMiddleware;