import logger from '../services/logger.js';
// CORS (single source of truth, applied early)
// The frontend calls the API with cookies.
// With credentials enabled we must NOT use '*', so we reflect only allowed origins.

const corsDebug = process.env.CORS_DEBUG === 'true';

function normalizeOrigin(value) {
  if (typeof value !== 'string') return value;
  return value.replace(/\/+$/, '');
}

const corsAllowList = new Set(
  [
    process.env.FRONTEND_URL,
    process.env.FRONTEND_URL2,
    'https://www.meniven.com',
    'https://api.meniven.com',
    'http://localhost:5173',
    'http://localhost:3000',
    'http://localhost:8080',
    'http://localhost:8081',
    'https://singular-catfish-deciding.ngrok-free.app',
    'https://qg048c0c0wos4o40gos4k0kc.128.140.43.244.sslip.io',
  ]
    .map(normalizeOrigin)
    .filter(Boolean),
);

const localSubnetRegex = /^http:\/\/192\.168\.1\.\d{1,3}(:\d+)?$/;

export function corsDelegate(req, callback) {
  const requestOrigin = normalizeOrigin(req.header('Origin'));

  // Non-browser/server-to-server requests don't need CORS headers.
  if (!requestOrigin) {
    if (corsDebug) logger.info('[CORS] No Origin header:', req.method, req.originalUrl);
    return callback(null, { origin: false });
  }

  const isAllowed = corsAllowList.has(requestOrigin) || localSubnetRegex.test(requestOrigin);
  if (!isAllowed) {
    if (corsDebug) logger.warn('[CORS] Blocked origin:', requestOrigin, req.method, req.originalUrl);
    return callback(null, { origin: false });
  }

  if (corsDebug) logger.info('[CORS] Allowed origin:', requestOrigin, req.method, req.originalUrl);

  return callback(null, {
    origin: requestOrigin,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    optionsSuccessStatus: 204,
  });
}
