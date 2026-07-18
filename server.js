import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import cron from 'node-cron';
import os from 'os';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import webPushPkg from 'web-push';
const webPush = webPushPkg && webPushPkg.default ? webPushPkg.default : webPushPkg;
import db from './connection.js';
import { queryPromise } from './dbUtils.js';
import { corsDelegate } from './config/cors.js';
import identifyUserMiddleware from './identifyUserMiddleware.js';
import { runDailyIngest } from './ingestScheduler.js';
import { formatDataToJson, extractSaleEndDateFromImage } from './services/aiService.js';
import { pollGeminiBatches } from './services/geminiBatchIngestService.js';
import { ensureAnonUserRow, handleInitialize } from './services/userService.js';
import { flattenFacebookPostsToItems } from './services/facebookService.js';
import { listAllMediaFiles } from './services/cloudinaryService.js';
import { subscribeWebPush, triggerAllWebPushNotifications } from './services/notificationService.js';
import {
  testPushNotification,
  triggerUserNotifications,
  triggerAllUserExpoNotifications,
  registerPushToken,
} from './controllers/notificationController.js';
import {
  getFacebookPhotos,
  getFacebookPostsHandler,
  getFacebookPhotosViaApify,
} from './controllers/facebookController.js';
import { ingestStoreDryRun, triggerDailyIngest, pollGeminiBatchesNow } from './controllers/ingestionController.js';
import { extractTextSingle } from './controllers/extractionController.js';
import { sendDailyProductNotifications } from './notificationScheduler.js';
import { errorHandler } from './middleware/errorHandler.js';
import logger from './services/logger.js';
import { requestLogger } from './middleware/requestLogger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// =========================================================================
// APP SETUP
// =========================================================================
export const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors(corsDelegate));
app.options('*', cors(corsDelegate));

// CSP
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "script-src 'self' https://singular-catfish-deciding.ngrok-free.app https://www.apple.com https://appleid.cdn-apple.com https://idmsa.apple.com https://gsa.apple.com https://idmsa.apple.com.cn https://signin.apple.com;",
  );
  next();
});

// Session
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 5 * 60 * 1000, secure: process.env.NODE_ENV === 'production' },
  }),
);

// Cookie & body parsing
app.use(cookieParser());
app.use(bodyParser.json());

// Request logging (adds req.log and req.reqId)
app.use(requestLogger);

// =========================================================================
// GOOGLE OAUTH SETUP
// =========================================================================
const keyFilePath = path.join(__dirname, './persistent/keys/vision-ai-455010-6d2a9944437b.json');
process.env.GOOGLE_APPLICATION_CREDENTIALS = keyFilePath;

const googleOAuthEnabled = Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

if (googleOAuthEnabled) {
  const backendBaseUrl = (process.env.BACKEND_URL || 'http://localhost:3000').replace(/\/+$/, '');
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || `${backendBaseUrl}/auth/google/callback`,
        passReqToCallback: true,
      },
      (req, accessToken, refreshToken, profile, done) => done(null, profile),
    ),
  );
}

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));
app.use(passport.initialize());
app.use(passport.session());

// =========================================================================
// VAPID WEB PUSH SETUP
// =========================================================================
const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;
const vapidAdminEmail = process.env.VAPID_ADMIN_EMAIL || 'admin@example.com';
const webPushEnabled = Boolean(vapidPublicKey && vapidPrivateKey);
if (webPushEnabled) {
  webPush.setVapidDetails(`mailto:${vapidAdminEmail}`, vapidPublicKey, vapidPrivateKey);
}

// =========================================================================
// USER IDENTIFICATION MIDDLEWARE
// =========================================================================
app.use(identifyUserMiddleware);

// =========================================================================
// EXISTING ROUTED ENDPOINTS (already in route files)
// =========================================================================
import authRoutes from './routes/authRoutes.js';
import jobLogRoutes from './routes/jobLogRoutes.js';
import userRoutes from './routes/userRoutes.js';
import flyerRoutes from './routes/flyerRoutes.js';
import productRoutes from './routes/productRoutes.js';
import storeRoutes from './routes/storeRoutes.js';
import notificationRoutes from './routes/notificationRoutes.js';
import facebookRoutes from './routes/facebookRoutes.js';
import cloudinaryRoutes from './routes/cloudinaryRoutes.js';
import ingestionRoutes from './routes/ingestionRoutes.js';
import extractionRoutes from './routes/extractionRoutes.js';
import searchRoutes from './routes/searchRoutes.js';
app.use('/auth', authRoutes);
app.use('/job-logs', jobLogRoutes);
app.use('/user', userRoutes);
app.use('/flyers', flyerRoutes);
app.use('/products', productRoutes);
app.use('/stores', storeRoutes);
app.use('/notifications', notificationRoutes);
app.use('/facebook', facebookRoutes);
app.use('/cloudinary', cloudinaryRoutes);
app.use('/ingestion', ingestionRoutes);
app.use('/extraction', extractionRoutes);
app.use(searchRoutes);

// =========================================================================
// WEB PUSH NOTIFICATION ENDPOINTS (original paths preserved)
// =========================================================================
app.post('/subscribe-webpush', (req, res) => subscribeWebPush(req, res));
app.post('/trigger-all-webpush', (req, res) => triggerAllWebPushNotifications(req, res));

// Expo push notification endpoints
app.post('/register-push-token', identifyUserMiddleware, (req, res) => registerPushToken(req, res));
app.post('/test-push', (req, res) => testPushNotification(req, res));
app.post('/trigger-user-notifications', (req, res) => triggerUserNotifications(req, res));
app.post('/trigger-all-user-expo-notifications', (req, res) => triggerAllUserExpoNotifications(req, res));

// =========================================================================
// FACEBOOK ENDPOINTS (original paths preserved)
// =========================================================================
app.get('/facebook-photos', (req, res) => getFacebookPhotos(req, res));
app.get('/facebook-posts', (req, res) => getFacebookPostsHandler(req, res));
app.post('/get-facebook-photos', (req, res) => getFacebookPhotosViaApify(req, res));

// =========================================================================
// INGESTION ENDPOINTS (original paths preserved)
// =========================================================================
app.post('/ingest-store-dry-run', (req, res) => ingestStoreDryRun(req, res));
app.post('/trigger-daily-ingest', (req, res) => triggerDailyIngest(req, res));
app.post('/poll-gemini-batches', (req, res) => pollGeminiBatchesNow(req, res));

// =========================================================================
// AI EXTRACTION ENDPOINTS (original paths preserved)
// =========================================================================
app.post('/extract-text-single', (req, res) => extractTextSingle(req, res));
app.post('/extract-sale-end-date', async (req, res) => {
  const { photos } = req.body;
  const imageUrls = photos;
  try {
    const results = [];
    for (const imageUrl of imageUrls) {
      let sale_end_date = null;
      try {
        sale_end_date = await extractSaleEndDateFromImage(imageUrl);
      } catch (err) {}
      results.push({ image: imageUrl, sale_end_date: sale_end_date || null });
    }
    return res.json(results);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to extract sale end date.', error: err.message });
  }
});

// =========================================================================
// USER INITIALIZATION ENDPOINTS
// =========================================================================
app.get('/initialize', handleInitialize);
app.get('/initialize0', handleInitialize);
app.get('/initialize2', handleInitialize);
app.get('/initialize-anonymous', async (req, res) => {
  try {
    const [result] = await db.promise().query('INSERT INTO users () VALUES ()');
    const userId = result.insertId;
    if (!userId) return res.status(500).json({ message: 'Failed to create anonymous user.' });
    const token = jwt.sign({ userId }, process.env.TOKEN_SECRET, { expiresIn: '2y' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error during initialization.' });
  }
});

// =========================================================================
// SESSION CHECK (full self-healing version)
// =========================================================================
app.get('/check-session', async (req, res) => {
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
              const u = repaired[0];
              return res.json({
                isLoggedIn: true,
                isRegistered: !!u.is_registered,
                userId: u.id,
                email: u.email ?? null,
                shouldReinitialize: false,
                reason: null,
                authSource,
              });
            }
          }
        } catch (e) {
          logger.error(`[check-session] self-heal failed:`, e);
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

    const u = results[0];
    return res.json({
      isLoggedIn: true,
      isRegistered: !!u.is_registered,
      userId: u.id,
      email: u.email ?? null,
      shouldReinitialize: false,
      reason: null,
      authSource,
    });
  } catch (err) {
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
});

// =========================================================================
// DASHBOARD & AUTH ENDPOINTS
// =========================================================================
app.post('/dashboardLogin', (req, res) => {
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
});

const getFrontendRedirectBase = () => {
  const raw = process.env.FRONTEND_URL || 'http://localhost:5173';
  return String(raw).replace(/\/\*$/, '').replace(/\/+$/, '');
};

const getGoogleCallbackUrl = () => {
  const fallbackBase = (process.env.BACKEND_URL || 'http://localhost:3000').replace(/\/+$/, '');
  return String(process.env.GOOGLE_CALLBACK_URL || `${fallbackBase}/auth/google/callback`).replace(/\/+$/, '');
};

const buildJwtCookieOptionsForRequest = (req) => {
  const forwardedProto = req.headers['x-forwarded-proto'];
  const isHttps = Boolean(req.secure) || (typeof forwardedProto === 'string' && forwardedProto.includes('https'));
  const host = String(req.headers.host || '').split(':')[0];
  const isMenivenDomain = host.endsWith('meniven.com');
  const isLocalHost = host === 'localhost' || host === '127.0.0.1';
  const isProduction = process.env.NODE_ENV === 'production' || isMenivenDomain;

  // On localhost, force non-secure cookies so browser always persists them on http://localhost.
  const useSecureCookie = isProduction ? isHttps : false;

  return {
    httpOnly: true,
    secure: useSecureCookie,
    sameSite: useSecureCookie ? 'None' : 'Lax',
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000,
    ...(isMenivenDomain && !isLocalHost ? { domain: '.meniven.com' } : {}),
  };
};

app.get('/auth/google', (req, res, next) => {
  if (!googleOAuthEnabled) {
    logger.warn('[GoogleOAuth] Disabled: missing client id/secret');
    return res.redirect(`${getFrontendRedirectBase()}/?auth=google_not_configured`);
  }

  logger.info(`[GoogleOAuth] Starting login flow callback=${getGoogleCallbackUrl()}`);

  return passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account',
    session: false,
    callbackURL: getGoogleCallbackUrl(),
  })(req, res, next);
});

app.get(
  '/auth/google/callback',
  (req, res, next) => {
    if (!googleOAuthEnabled) {
      logger.warn('[GoogleOAuth] Callback hit while Google OAuth is disabled');
      return res.redirect(`${getFrontendRedirectBase()}/?auth=google_not_configured`);
    }

    logger.info('[GoogleOAuth] Callback received, authenticating Google user');
    return passport.authenticate('google', { session: false }, (err, user, info) => {
      if (err) {
        logger.error('Google OAuth passport error:', err);
        const reason = encodeURIComponent(err.message || 'passport_error');
        return res.redirect(`${getFrontendRedirectBase()}/?auth=google_failed&reason=${reason}`);
      }

      if (!user) {
        logger.warn('[GoogleOAuth] Passport did not return a user', info);
        const reason = encodeURIComponent(info?.message || info?.name || 'no_user');
        return res.redirect(`${getFrontendRedirectBase()}/?auth=google_failed&reason=${reason}`);
      }

      req.user = user;
      logger.info(`[GoogleOAuth] Passport success for googleId=${user?.id || 'n/a'}`);
      return next();
    })(req, res, next);
  },
  async (req, res) => {
    try {
      if (!process.env.TOKEN_SECRET) {
        logger.error('[GoogleOAuth] TOKEN_SECRET missing');
        return res.redirect(`${getFrontendRedirectBase()}/?auth=google_error`);
      }

      const googleId = req.user?.id ? String(req.user.id) : null;
      const profileEmail = String(req.user?.emails?.[0]?.value || '').trim().toLowerCase();
      const email = profileEmail || null;
      const firstName = String(req.user?.name?.givenName || '').trim();
      const lastName = String(req.user?.name?.familyName || '').trim();

      if (!googleId || !email) {
        return res.redirect(`${getFrontendRedirectBase()}/?auth=google_missing_profile`);
      }

      const columnRows = await queryPromise(
        `SELECT COUNT(*) AS count
           FROM information_schema.columns
          WHERE table_schema = DATABASE()
            AND table_name = 'users'
            AND column_name = 'googleId'`,
        [],
      );
      const hasGoogleIdColumn = Number(columnRows?.[0]?.count || 0) > 0;

      const existingRows = await queryPromise(
        hasGoogleIdColumn
          ? `SELECT id, userId, email FROM users WHERE googleId = ? OR email = ? ORDER BY id DESC LIMIT 1`
          : `SELECT id, userId, email FROM users WHERE email = ? ORDER BY id DESC LIMIT 1`,
        hasGoogleIdColumn ? [googleId, email] : [email],
      );

      let dbUserId;
      if (Array.isArray(existingRows) && existingRows.length > 0) {
        logger.info(`[GoogleOAuth] Linking existing user id=${existingRows[0].id} googleId=${googleId}`);
        dbUserId = existingRows[0].id;
        const updateSql = hasGoogleIdColumn
          ? `UPDATE users
             SET googleId = ?, email = ?, first_name = COALESCE(NULLIF(first_name, ''), ?), last_name = COALESCE(NULLIF(last_name, ''), ?), is_registered = 1
             WHERE id = ?`
          : `UPDATE users
             SET email = ?, first_name = COALESCE(NULLIF(first_name, ''), ?), last_name = COALESCE(NULLIF(last_name, ''), ?), is_registered = 1
             WHERE id = ?`;
        const updateParams = hasGoogleIdColumn
          ? [googleId, email, firstName || 'Google', lastName || '', dbUserId]
          : [email, firstName || 'Google', lastName || '', dbUserId];
        await queryPromise(updateSql, updateParams);
      } else {
        const publicUserId = `google_${googleId}`;
        logger.info(`[GoogleOAuth] Creating new Google user publicUserId=${publicUserId}`);
        const insertSql = hasGoogleIdColumn
          ? `INSERT INTO users (userId, first_name, last_name, email, googleId, is_registered, timestamp)
             VALUES (?, ?, ?, ?, ?, 1, NOW())`
          : `INSERT INTO users (userId, first_name, last_name, email, is_registered, timestamp)
             VALUES (?, ?, ?, ?, 1, NOW())`;
        const insertParams = hasGoogleIdColumn
          ? [publicUserId, firstName || 'Google', lastName || '', email, googleId]
          : [publicUserId, firstName || 'Google', lastName || '', email];
        const insertResult = await queryPromise(insertSql, insertParams);
        dbUserId = insertResult?.insertId;
      }

      if (!dbUserId) {
        logger.error('[GoogleOAuth] Could not resolve dbUserId after upsert');
        return res.redirect(`${getFrontendRedirectBase()}/?auth=google_error`);
      }

      const token = jwt.sign({ userId: dbUserId, email }, process.env.TOKEN_SECRET, { expiresIn: '30d' });
      const cookieOptions = buildJwtCookieOptionsForRequest(req);
      logger.info('[GoogleOAuth] Setting jwt cookie options', {
        secure: cookieOptions.secure,
        sameSite: cookieOptions.sameSite,
        domain: cookieOptions.domain || null,
        path: cookieOptions.path || null,
        maxAge: cookieOptions.maxAge,
        reqHost: req.headers.host || null,
        forwardedProto: req.headers['x-forwarded-proto'] || null,
      });
      res.cookie('jwt', token, cookieOptions);
      logger.info(`[GoogleOAuth] Login complete dbUserId=${dbUserId} email=${email}`);
      return res.redirect(`${getFrontendRedirectBase()}/?auth=google_success`);
    } catch (err) {
      logger.error('Google OAuth callback failed:', err);
      return res.redirect(`${getFrontendRedirectBase()}/?auth=google_error`);
    }
  },
);

// =========================================================================
// USER PREFERENCES
// =========================================================================
const requireUser = (req, res, next) => {
  if (!req.identifiedUser?.userId) return res.status(401).json({ error: 'User identification required.' });
  next();
};

app.get('/user/preferences', requireUser, async (req, res) => {
  try {
    const [user] = await queryPromise(
      'SELECT first_name, last_name, email, notification_frequency FROM users WHERE id = ?',
      [req.identifiedUser.userId],
    );
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
});

app.put('/user/preferences', requireUser, async (req, res) => {
  const { notificationFrequency } = req.body;
  if (!['daily', 'weekly', 'monthly', 'off'].includes(notificationFrequency))
    return res.status(400).json({ error: 'Invalid frequency.' });
  try {
    await queryPromise('UPDATE users SET notification_frequency = ? WHERE id = ?', [
      notificationFrequency,
      req.identifiedUser.userId,
    ]);
    res.json({ message: 'Preferences updated.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update preferences.' });
  }
});

// =========================================================================
// STORE ENDPOINTS
// =========================================================================
app.get('/getStores', (req, res) => {
  db.query('SELECT * from stores WHERE facebookPageId > 0 and active = true order by storeId asc', (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

app.get('/getFaceBookStores', (req, res) => {
  db.query('SELECT * from stores WHERE facebookPageId IS NOT NULL ORDER BY storeId ASC', (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

// =========================================================================
// PRODUCT ENDPOINTS (original paths preserved)
// =========================================================================
app.get('/getProducts', async (req, res) => {
  const userId = req.identifiedUser?.id ?? req.identifiedUser?.userId ?? null;
  const numericUserId =
    typeof userId === 'number'
      ? userId
      : typeof userId === 'string' && /^\d+$/.test(userId)
        ? parseInt(userId, 10)
        : null;

  const storeIdsParam = req.query.storeId || req.query.storeIds || '';
  let storeIds = null;
  if (storeIdsParam && typeof storeIdsParam === 'string') {
    const parsed = storeIdsParam
      .split(',')
      .map((s) => parseInt(s.trim(), 10))
      .filter(Number.isFinite);
    if (parsed.length > 0) storeIds = parsed;
  }

  const isFavoriteQueryParam = req.query.isFavorite === 'true';
  const onSale = req.query.onSale === 'true';
  const keywordQuery = req.query.keyword || null;
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const offset = (page - 1) * limit;
  const today = new Date().toISOString().split('T')[0];

  const searchKeywordsArray = keywordQuery
    ? keywordQuery
        .split(' ')
        .map((kw) => kw.trim())
        .filter((kw) => kw.length > 1)
    : [];
  let matchedKeywordCountSelectSQL = '0 AS matched_keyword_count';
  const paramsForMatchedKeywordCountSubquery = [];

  if (searchKeywordsArray.length > 0) {
    const matchConditionsForSubquery = searchKeywordsArray.map(() => `sk_match.keyword LIKE ?`).join(' OR ');
    matchedKeywordCountSelectSQL = `(SELECT COUNT(DISTINCT sk_match.keywordId) FROM productkeywords pk_match JOIN keywords sk_match ON pk_match.keywordId = sk_match.keywordId WHERE pk_match.productId = p.productId AND (${matchConditionsForSubquery})) AS matched_keyword_count`;
    searchKeywordsArray.forEach((kw) => paramsForMatchedKeywordCountSubquery.push(`${kw}%`));
  }

  let fromAndJoins = `FROM products p LEFT JOIN stores s ON p.storeId = s.storeId LEFT JOIN productkeywords pk ON p.productId = pk.productId LEFT JOIN productcategories pc ON p.category_id = pc.categoryId LEFT JOIN keywords k ON pk.keywordId = k.keywordId ${numericUserId ? `LEFT JOIN favorites f ON p.productId = f.productId AND f.userId = ?` : ''}`;

  let q = `SELECT p.productId, p.product_description, p.old_price, p.new_price, p.discount_percentage, p.sale_end_date, p.storeId, p.image_url, s.storeName, s.logoUrl, p.flyer_book_id, ANY_VALUE(pc.categoryWeight) AS categoryWeight, GROUP_CONCAT(DISTINCT k.keyword SEPARATOR ',') AS keywords, ${matchedKeywordCountSelectSQL}, ${numericUserId ? 'CASE WHEN f.userId IS NOT NULL THEN TRUE ELSE FALSE END' : 'FALSE'} AS isFavorite, CASE WHEN p.sale_end_date >= ? THEN TRUE ELSE FALSE END AS productOnSale ${fromAndJoins}`;

  const selectParams = [];
  selectParams.push(...paramsForMatchedKeywordCountSubquery);
  selectParams.push(today);
  if (numericUserId) selectParams.push(numericUserId);

  let conditions = [];
  const whereParams = [];

  if (Array.isArray(storeIds) && storeIds.length > 0) {
    const placeholders = storeIds.map(() => '?').join(',');
    conditions.push(`p.storeId IN (${placeholders})`);
    whereParams.push(...storeIds);
  }

  if (isFavoriteQueryParam && numericUserId) {
    conditions.push(
      `EXISTS (SELECT 1 FROM favorites fav_sub WHERE fav_sub.productId = p.productId AND fav_sub.userId = ?)`,
    );
    whereParams.push(numericUserId);
  }

  if (onSale) {
    conditions.push(`p.sale_end_date >= ?`);
    whereParams.push(today);
  }

  if (searchKeywordsArray.length > 0) {
    const keywordTableConditions = searchKeywordsArray.map(() => `k.keyword LIKE ?`).join(' OR ');
    const descConditions = searchKeywordsArray.map(() => `p.product_description LIKE ?`).join(' OR ');
    conditions.push(`((${keywordTableConditions}) OR (${descConditions}))`);
    searchKeywordsArray.forEach((kw) => {
      whereParams.push(`${kw}%`);
    });
    searchKeywordsArray.forEach((kw) => {
      whereParams.push(`${kw}%`);
    });
  }

  if (conditions.length > 0) q += ' WHERE ' + conditions.join(' AND ');

  let countQ = `SELECT COUNT(DISTINCT p.productId) AS totalItems ${fromAndJoins}`;
  const countParams = [];
  if (numericUserId) countParams.push(numericUserId);
  const countConditions = [...conditions, 'p.sale_end_date >= ?'];
  const countWhereParams = [...whereParams, today];
  if (countConditions.length > 0) {
    countQ += ' WHERE ' + countConditions.join(' AND ');
    countParams.push(...countWhereParams);
  }

  q += ` GROUP BY p.productId ORDER BY matched_keyword_count DESC, productOnSale DESC, categoryWeight DESC, p.productId DESC LIMIT ? OFFSET ?`;
  const finalParams = [...selectParams, ...whereParams, limit, offset];

  try {
    const [data, totalResult] = await Promise.all([queryPromise(q, finalParams), queryPromise(countQ, countParams)]);
    const nextPage = data.length === limit ? page + 1 : null;
    const totalItems = Number(totalResult?.[0]?.totalItems || 0);
    return res.json({ data, nextPage, totalItems });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve products' });
  }
});

app.get('/getProductsDashboard', async (req, res) => {
  const userId = parseInt(req.query.userId, 10) || null;
  let storeId = parseInt(req.query.storeId, 10);
  const isFavorite = req.query.isFavorite || null;
  const onSale = req.query.onSale || null;
  const keyword = req.query.keyword || null;
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const offset = (page - 1) * limit;
  const today = new Date().toISOString().split('T')[0];
  if (isNaN(storeId) || storeId <= 0) storeId = null;

  let q = `SELECT p.productId, p.product_description, p.old_price, p.new_price, p.discount_percentage, p.sale_end_date, p.storeId, p.image_url, s.storeName, GROUP_CONCAT(k.keyword) AS keywords, CASE WHEN f.userId IS NOT NULL THEN TRUE ELSE FALSE END AS isFavorite, CASE WHEN p.sale_end_date >= ? THEN TRUE ELSE FALSE END AS productOnSale, (SELECT COUNT(*) FROM productkeywords pkf JOIN keywords kf ON pkf.keywordId = kf.keywordId WHERE pkf.productId = p.productId AND kf.keyword IN (SELECT k.keyword FROM favorites f_sub JOIN productkeywords pk ON f_sub.productId = pk.productId JOIN keywords k ON pk.keywordId = k.keywordId WHERE f_sub.userId = ?)) AS keywordMatchCount FROM products p LEFT JOIN productkeywords pk ON p.productId = pk.productId LEFT JOIN keywords k ON pk.keywordId = k.keywordId LEFT JOIN favorites f ON p.productId = f.productId AND f.userId = ? LEFT JOIN stores s ON p.storeId = s.storeId`;

  const params = [today, userId, userId];
  let conditions = [];
  if (storeId !== null) {
    conditions.push('p.storeId = ?');
    params.push(storeId);
  }
  if (isFavorite && isFavorite.trim() === 'true') {
    conditions.push('f.userId = ?');
    params.push(userId);
  }
  if (onSale === 'true') {
    conditions.push('p.sale_end_date >= ?');
    params.push(today);
  }
  if (keyword) {
    const keywords = keyword.split(' ').map((kw) => kw.trim());
    const kwConditions = keywords
      .filter((kw) => kw.length > 1)
      .map(() => 'k.keyword LIKE ?')
      .join(' OR ');
    if (kwConditions.length > 0) {
      conditions.push(`(${kwConditions})`);
      params.push(...keywords.map((kw) => `%${kw}%`));
    }
  }

  if (conditions.length > 0) q += ' WHERE ' + conditions.join(' AND ');
  q += ` GROUP BY p.productId ORDER BY p.productId DESC, productOnSale DESC, isFavorite DESC, keywordMatchCount DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);

  db.query(q, params, (err, data) => {
    if (err) return res.json(err);
    const nextPage = data.length === limit ? page + 1 : null;
    return res.json({ data, nextPage });
  });
});

app.delete('/deleteProduct/:productId', async (req, res) => {
  const productId = req.params.productId;
  const dbQuery = (q, p) =>
    new Promise((resolve, reject) => {
      db.query(q, p, (e, r) => {
        if (e) return reject(e);
        resolve(r);
      });
    });
  try {
    await dbQuery('START TRANSACTION');
    await dbQuery('DELETE FROM productkeywords WHERE productId = ?', [productId]);
    await dbQuery('DELETE FROM keywords WHERE keywordId NOT IN (SELECT keywordId FROM productkeywords)');
    await dbQuery('DELETE FROM products WHERE productId = ?', [productId]);
    await dbQuery('COMMIT');
    res.status(200).json({ message: 'Product and related data deleted successfully.' });
  } catch (error) {
    await dbQuery('ROLLBACK');
    res.status(500).json({ message: 'An error occurred while deleting the product.' });
  }
});

app.put('/updateProductPrices', (req, res) => {
  const { productId, oldPrice, newPrice } = req.body;
  db.query(
    'UPDATE products SET old_price = ?, new_price = ? WHERE productId = ?',
    [oldPrice, newPrice, productId],
    (err) => {
      if (err) return res.status(500).json({ error: 'Failed to update prices' });
      res.status(200).json({ message: 'Prices updated successfully' });
    },
  );
});

app.put('/editProductDescription', (req, res) => {
  const { productId, newDescription } = req.body;
  db.query('UPDATE products SET product_description = ? WHERE productId = ?', [newDescription, productId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update description' });
    res.status(200).json({ message: 'Description updated successfully' });
  });
});

app.put('/editProductSaleDate', (req, res) => {
  const { productId, sale_end_date } = req.body;
  const formattedDate = new Date(sale_end_date).toISOString().slice(0, 19).replace('T', ' ');
  db.query('UPDATE products SET sale_end_date = ? WHERE productId = ?', [formattedDate, productId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update date' });
    res.status(200).json({ message: 'Date updated successfully' });
  });
});

app.put('/editStore', (req, res) => {
  const { productId, storeId } = req.body;
  db.query('UPDATE products SET storeId = ? WHERE productId = ?', [storeId, productId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update store' });
    res.status(200).json({ message: 'Store updated successfully' });
  });
});

async function probeAndLogBrokenImage({
  productId,
  imageUrl,
  sourcePage,
  logPrefix,
  extraDetails = {},
}) {
  const normalizedUrl = String(imageUrl || '').trim();
  if (!normalizedUrl) return { status: 'skipped' };

  const shouldInsertForUrl = async (url) => {
    const existing = await queryPromise(
      `SELECT id
         FROM broken_image_logs
        WHERE failing_url = ?
        LIMIT 1`,
      [url],
    );
    return (existing?.length || 0) === 0;
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const probeResponse = await fetch(normalizedUrl, {
      method: 'GET',
      signal: controller.signal,
    }).catch((probeErr) => {
      clearTimeout(timeout);
      throw probeErr;
    });
    clearTimeout(timeout);

    if (!probeResponse.ok) {
      logger.info(
        `${logPrefix} status=${probeResponse.status} url=${normalizedUrl} productId=${productId || 'n/a'}`,
      );
      const shouldInsert = await shouldInsertForUrl(normalizedUrl);
      if (shouldInsert) {
        await queryPromise(
          `INSERT INTO broken_image_logs
            (product_id, raw_product_image_url, attempted_cloudinary_url, failing_url, client_error, source_page, extra_details)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            productId || null,
            normalizedUrl,
            normalizedUrl,
            normalizedUrl,
            `probe-status-${probeResponse.status}`,
            sourcePage,
            JSON.stringify({ reportedAt: new Date().toISOString(), probeStatus: probeResponse.status, ...extraDetails }),
          ],
        );
      } else {
        logger.info(`${logPrefix} duplicate-url-skipped url=${normalizedUrl}`);
      }
      return { status: 'broken', probeStatus: probeResponse.status };
    }

    logger.info(`${logPrefix} ok url=${normalizedUrl} productId=${productId || 'n/a'}`);
    return { status: 'ok' };
  } catch (probeError) {
    logger.info(
      `${logPrefix} failed url=${normalizedUrl} error=${probeError.message} productId=${productId || 'n/a'}`,
    );
    try {
      const shouldInsert = await shouldInsertForUrl(normalizedUrl);
      if (shouldInsert) {
        await queryPromise(
          `INSERT INTO broken_image_logs
            (product_id, raw_product_image_url, attempted_cloudinary_url, failing_url, client_error, source_page, extra_details)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            productId || null,
            normalizedUrl,
            normalizedUrl,
            normalizedUrl,
            probeError.message || 'probe-failed',
            sourcePage,
            JSON.stringify({ reportedAt: new Date().toISOString(), ...extraDetails }),
          ],
        );
      } else {
        logger.info(`${logPrefix} duplicate-url-skipped url=${normalizedUrl}`);
      }
    } catch (insertErr) {
      logger.error('Failed to write broken image probe log:', insertErr.message);
    }
    return { status: 'failed', error: probeError.message };
  }
}

app.put('/editProductImageUrl', (req, res) => {
  const { productId, imageUrl } = req.body;
  if (!productId) return res.status(400).json({ error: 'productId is required' });
  db.query('UPDATE products SET image_url = ? WHERE productId = ?', [imageUrl || null, productId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update image URL' });

    const normalizedImageUrl = imageUrl || null;
    res.status(200).json({ message: 'Image URL updated successfully' });

    if (!normalizedImageUrl) return;

    void probeAndLogBrokenImage({
      productId,
      imageUrl: normalizedImageUrl,
      sourcePage: 'dashboard-edit-product-url',
      logPrefix: '[BrokenImage][EDIT-PROBE]',
    });
  });
});

app.post('/report-broken-product-image', async (req, res) => {
  const {
    productId,
    storeId,
    storeName,
    rawProductImageUrl,
    attemptedCloudinaryUrl,
    failingUrl,
    facebookPostId,
    facebookImageId,
    facebookTimestamp,
    clientError,
    sourcePage,
    userAgent,
  } = req.body || {};

  try {
    let enriched = null;
    if (productId) {
      const rows = await queryPromise(
        `SELECT p.productId, p.storeId, p.image_url, p.postId, p.imageId, p.timestamp,
                s.storeName, s.facebookUrl, s.facebookPageId
           FROM products p
      LEFT JOIN stores s ON p.storeId = s.storeId
          WHERE p.productId = ?
          LIMIT 1`,
        [productId],
      );
      enriched = rows?.[0] || null;
    }

    const resolvedProductId = enriched?.productId || productId || null;
    const resolvedStoreId = enriched?.storeId || storeId || null;
    const resolvedRawUrl = enriched?.image_url || rawProductImageUrl || null;
    const resolvedCloudinaryUrl = attemptedCloudinaryUrl || null;
    const resolvedFailingUrl = failingUrl || null;
    const dedupeUrl = String(resolvedFailingUrl || resolvedCloudinaryUrl || resolvedRawUrl || '').trim();

    logger.info(
      `[BrokenImage][REPORT] productId=${resolvedProductId || 'n/a'} storeId=${resolvedStoreId || 'n/a'} error=${clientError || 'unknown'} rawUrl=${resolvedRawUrl || 'n/a'} cloudinaryUrl=${resolvedCloudinaryUrl || 'n/a'} failingUrl=${resolvedFailingUrl || 'n/a'}`,
    );

    if (!dedupeUrl) {
      return res.status(400).json({ error: 'A valid failingUrl/cloudinaryUrl/rawProductImageUrl is required' });
    }

    const existing = await queryPromise(
      `SELECT id
         FROM broken_image_logs
        WHERE failing_url = ?
        LIMIT 1`,
      [dedupeUrl],
    );
    if ((existing?.length || 0) > 0) {
      logger.info(`[BrokenImage][REPORT] duplicate-url-skipped url=${dedupeUrl}`);
      return res.status(200).json({ message: 'Duplicate broken image URL skipped.' });
    }

    await queryPromise(
      `INSERT INTO broken_image_logs
        (product_id, store_id, store_name, store_facebook_url, store_facebook_page_id,
         facebook_post_id, facebook_image_id, facebook_timestamp,
         raw_product_image_url, attempted_cloudinary_url, failing_url,
         client_error, source_page, user_agent, extra_details)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        resolvedProductId,
        resolvedStoreId,
        enriched?.storeName || storeName || null,
        enriched?.facebookUrl || null,
        enriched?.facebookPageId || null,
        enriched?.postId || facebookPostId || null,
        enriched?.imageId || facebookImageId || null,
        enriched?.timestamp || facebookTimestamp || null,
        resolvedRawUrl,
        resolvedCloudinaryUrl,
        dedupeUrl,
        clientError || 'unknown',
        sourcePage || null,
        userAgent || null,
        JSON.stringify({ reportedAt: new Date().toISOString() }),
      ],
    );

    logger.info(
      `[BrokenImage][SAVED] productId=${resolvedProductId || 'n/a'} storeId=${resolvedStoreId || 'n/a'} failingUrl=${resolvedFailingUrl || resolvedCloudinaryUrl || resolvedRawUrl || 'n/a'}`,
    );

    return res.status(201).json({ message: 'Broken image log saved.' });
  } catch (error) {
    logger.error('Failed to save broken image log:', error.message);
    return res.status(500).json({ error: 'Failed to save broken image log' });
  }
});

app.post('/scan-broken-product-images', async (req, res) => {
  const requestedProductId = req.body?.productId || req.query?.productId || null;
  const requestedUrl = String(req.body?.url || req.query?.url || '').trim();
  const requestedLimitRaw = parseInt(req.body?.limit || req.query?.limit, 10);
  const limit = Number.isFinite(requestedLimitRaw) && requestedLimitRaw > 0 ? Math.min(requestedLimitRaw, 500) : 100;

  try {
    let rows = [];
    if (requestedUrl) {
      rows = [{ productId: null, image_url: requestedUrl }];
    } else if (requestedProductId) {
      rows = await queryPromise(
        `SELECT p.productId, p.image_url
           FROM products p
          WHERE p.productId = ?
          LIMIT 1`,
        [requestedProductId],
      );
    } else {
      rows = await queryPromise(
        `SELECT MIN(p.productId) AS productId, p.image_url
           FROM products p
          WHERE p.image_url IS NOT NULL AND p.image_url <> ''
       GROUP BY p.image_url
       ORDER BY MIN(p.productId) DESC
          LIMIT ?`,
        [limit],
      );
    }

    let scanned = 0;
    let broken = 0;
    let skipped = 0;

    for (const row of rows) {
      if (!row?.image_url) {
        skipped += 1;
        continue;
      }

      scanned += 1;
      const result = await probeAndLogBrokenImage({
        productId: row.productId || null,
        imageUrl: row.image_url,
        sourcePage: 'dashboard-manual-scan',
        logPrefix: '[BrokenImage][SCAN]',
        extraDetails: { requestedProductId, requestedUrl, limit },
      });
      if (result.status === 'broken' || result.status === 'failed') broken += 1;
    }

    return res.status(200).json({
      message: 'Broken image scan complete.',
      scanned,
      broken,
      skipped,
      limit,
      productId: requestedProductId || null,
      url: requestedUrl || null,
    });
  } catch (error) {
    logger.error('Failed to scan broken image urls:', error.message);
    return res.status(500).json({ error: 'Failed to scan broken image urls' });
  }
});

app.get('/broken-image-logs', async (req, res) => {
  const limitRaw = parseInt(req.query.limit, 10);
  const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 500) : 200;

  try {
    const rows = await queryPromise(
      `SELECT id, product_id, store_id, store_name, store_facebook_url, store_facebook_page_id,
              facebook_post_id, facebook_image_id, facebook_timestamp,
              raw_product_image_url, attempted_cloudinary_url, failing_url,
              client_error, source_page, user_agent, created_at
         FROM broken_image_logs
     ORDER BY created_at DESC
        LIMIT ?`,
      [limit],
    );

    return res.status(200).json({ data: rows });
  } catch (error) {
    logger.error('Failed to fetch broken image logs:', error.message);
    return res.status(500).json({ error: 'Failed to fetch broken image logs' });
  }
});

app.get('/ingest-rejected-products', async (req, res) => {
  const limitRaw = parseInt(req.query.limit, 10);
  const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 1000) : 300;

  try {
    const rows = await queryPromise(
      `SELECT id, source, reason, store_id, user_id, post_id, image_id, flyer_book_id,
              image_url, product_description, old_price_raw, new_price_raw, sale_end_date_raw,
              raw_payload, created_at
         FROM ingest_rejected_products
     ORDER BY created_at DESC
        LIMIT ?`,
      [limit],
    );

    return res.status(200).json({ data: rows });
  } catch (error) {
    logger.error('Failed to fetch ingest rejected products logs:', error.message);
    return res.status(500).json({ error: 'Failed to fetch ingest rejected products logs' });
  }
});

app.get('/getProductsWithKeywords', (req, res) => {
  const requestedLimit = parseInt(req.query.limit, 10);
  const limit = Number.isFinite(requestedLimit) && requestedLimit > 0 ? Math.min(requestedLimit, 2000) : 100;
  db.query(
    "SELECT p.productId, p.product_description, p.old_price, p.new_price, p.discount_percentage, p.sale_end_date, p.storeId, p.image_url, GROUP_CONCAT(k.keyword SEPARATOR ', ') AS keywords FROM products p LEFT JOIN productkeywords pk ON p.productId = pk.productId LEFT JOIN keywords k ON pk.keywordId = k.keywordId GROUP BY p.productId ORDER BY p.productId desc LIMIT ?",
    [limit],
    (err, data) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch' });
      return res.json(data);
    },
  );
});

app.get('/searchProducts', (req, res) => {
  const { keyword } = req.query;
  let q =
    'SELECT p.productId, p.product_description, p.old_price, p.new_price, p.discount_percentage, p.sale_end_date, p.storeId, p.image_url, GROUP_CONCAT(k.keyword) AS keywords FROM products p LEFT JOIN productkeywords pk ON p.productId = pk.productId LEFT JOIN keywords k ON pk.keywordId = k.keywordId';
  const queryParams = [];
  if (keyword) {
    const keywords = keyword.split(' ').map((kw) => kw.trim());
    const kwConditions = keywords
      .filter((kw) => kw.length > 1)
      .map(() => 'k.keyword LIKE ?')
      .join(' OR ');
    q += ` WHERE ${kwConditions}`;
    queryParams.push(...keywords.map((kw) => `%${kw}%`));
  }
  q += ' GROUP BY p.productId';
  db.query(q, queryParams, (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to search' });
    res.status(200).json(results);
  });
});

app.post('/addKeyword', (req, res) => {
  const { productId, keyword } = req.body;
  db.query(
    'INSERT INTO keywords (keyword) VALUES (?) ON DUPLICATE KEY UPDATE keywordId = LAST_INSERT_ID(keywordId)',
    [keyword],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Failed to add keyword' });
      const keywordId = result.insertId;
      db.query('INSERT INTO productkeywords (productId, keywordId) VALUES (?, ?)', [productId, keywordId], (err) => {
        if (err) return res.status(500).json({ error: 'Failed to add keyword to product' });
        res.status(200).json({ message: 'Keyword added successfully' });
      });
    },
  );
});

app.delete('/removeKeyword', (req, res) => {
  const { productId, keyword } = req.body;
  db.query('SELECT keywordId FROM keywords WHERE keyword = ?', [keyword], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to get keywordId' });
    const keywordId = result[0]?.keywordId;
    db.query('DELETE FROM productkeywords WHERE productId = ? AND keywordId = ?', [productId, keywordId], (err) => {
      if (err) return res.status(500).json({ error: 'Failed to remove keyword' });
      res.status(200).json({ message: 'Keyword removed successfully' });
    });
  });
});

app.get('/products-by-ids', async (req, res) => {
  const { ids } = req.query;
  const userId = req.identifiedUser ? req.identifiedUser.userId : null;
  if (!ids) return res.status(400).json({ error: 'Product IDs are required.' });
  const productIds = ids
    .split(',')
    .map((id) => parseInt(id.trim(), 10))
    .filter(Number.isFinite);
  if (productIds.length === 0) return res.status(400).json({ error: 'No valid product IDs provided.' });
  try {
    const products = await queryPromise(
      'SELECT p.*, f.userId IS NOT NULL AS isFavorite FROM products p LEFT JOIN favorites f ON p.productId = f.productId AND f.userId = ? WHERE p.productId IN (?)',
      [userId, productIds],
    );
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch products.' });
  }
});

app.get('/isFavorite', async (req, res) => {
  const userId = req.identifiedUser?.id ?? req.identifiedUser?.userId ?? null;
  const productId = parseInt(req.query.productId, 10);
  const numUserId =
    typeof userId === 'number'
      ? userId
      : typeof userId === 'string' && /^\d+$/.test(userId)
        ? parseInt(userId, 10)
        : null;
  if (!numUserId || !Number.isFinite(productId) || productId <= 0) return res.status(200).json({ isFavorite: false });
  try {
    const result = await queryPromise('SELECT 1 FROM favorites WHERE userId = ? AND productId = ? LIMIT 1', [
      numUserId,
      productId,
    ]);
    res.status(200).json({ isFavorite: result.length > 0 });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check favorite' });
  }
});

app.post('/addFavorite', async (req, res) => {
  if (!req.identifiedUser || !req.identifiedUser.userId)
    return res.status(401).json({ error: 'User identification required.' });
  const tokenUserId = req.identifiedUser?.userId ?? null;
  const userId = req.identifiedUser?.id ?? tokenUserId ?? null;
  const productId = parseInt(req.body?.productId, 10);
  let numUserId =
    typeof userId === 'number'
      ? userId
      : typeof userId === 'string' && /^\d+$/.test(userId)
        ? parseInt(userId, 10)
        : null;

  if (!numUserId && typeof tokenUserId === 'string' && tokenUserId.trim() !== '') {
    try {
      const existing = await queryPromise('SELECT id FROM users WHERE userId = ? ORDER BY id DESC LIMIT 1', [
        tokenUserId,
      ]);
      if (Array.isArray(existing) && existing[0]?.id) {
        numUserId = existing[0].id;
      } else {
        await queryPromise('INSERT INTO users (userId, is_registered, `timestamp`) VALUES (?, ?, NOW())', [
          tokenUserId,
          false,
        ]);
        const created = await queryPromise('SELECT id FROM users WHERE userId = ? ORDER BY id DESC LIMIT 1', [
          tokenUserId,
        ]);
        if (Array.isArray(created) && created[0]?.id) numUserId = created[0].id;
      }
    } catch (resolveErr) {
      logger.error('Failed to resolve user id:', resolveErr);
    }
  }

  if (!numUserId) return res.status(401).json({ error: 'User identification required.' });
  if (!Number.isFinite(productId) || productId <= 0)
    return res.status(400).json({ error: 'Valid Product ID is required.' });

  try {
    const result = await queryPromise(
      'INSERT INTO favorites (userId, productId) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM favorites WHERE userId = ? AND productId = ?)',
      [numUserId, productId, numUserId, productId],
    );
    const added = Boolean(result?.affectedRows);
    res.status(200).json({ message: added ? 'Favorite added successfully' : 'Favorite already exists', added });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to add favorite' });
  }
});

app.delete('/removeFavorite', async (req, res) => {
  if (!req.identifiedUser || !req.identifiedUser.userId)
    return res.status(401).json({ error: 'User identification required.' });
  const userId = req.identifiedUser?.id ?? req.identifiedUser?.userId ?? null;
  const numUserId =
    typeof userId === 'number'
      ? userId
      : typeof userId === 'string' && /^\d+$/.test(userId)
        ? parseInt(userId, 10)
        : null;
  if (!numUserId) return res.status(401).json({ error: 'User identification required.' });
  const productId = parseInt(req.body?.productId ?? req.query.productId, 10);
  if (!Number.isFinite(productId) || productId <= 0)
    return res.status(400).json({ error: 'Valid Product ID is required.' });
  try {
    await queryPromise('DELETE FROM favorites WHERE userId = ? AND productId = ?', [numUserId, productId]);
    res.status(200).json({ message: 'Favorite removed successfully' });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to remove favorite' });
  }
});

app.get('/getImagesByFlyerBookId', (req, res) => {
  db.query('SELECT DISTINCT image_url FROM products WHERE flyer_book_id = ?', [req.query.flyerBookId], (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

// =========================================================================
// CLOUDINARY ENDPOINTS (original paths preserved)
// =========================================================================
const upload = multer({ dest: 'uploads/' });

app.get('/media-library-json', async (req, res) => {
  const mediaJson = await listAllMediaFiles();
  res.json(mediaJson);
});

app.put('/rename-image', async (req, res) => {
  const { public_id, new_name } = req.body;
  if (!public_id || !new_name) return res.status(400).json({ error: 'Missing public_id or new_name' });
  try {
    const cloudinary = (await import('./cloudinaryConfig.js')).default;
    const result = await cloudinary.uploader.rename(public_id, new_name);
    if (result.result === 'ok') res.status(200).json({ message: 'Image renamed successfully' });
    else res.status(500).json({ error: 'Failed to rename image' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/delete-image', async (req, res) => {
  const { public_id } = req.body;
  if (!public_id) return res.status(400).json({ error: 'Missing public_id' });
  try {
    const cloudinary = (await import('./cloudinaryConfig.js')).default;
    const result = await cloudinary.uploader.destroy(public_id);
    if (result.result === 'ok') res.status(200).json({ message: 'Image deleted successfully' });
    else res.status(500).json({ error: 'Failed to delete image' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/upload', upload.array('images', 10), async (req, res) => {
  try {
    const cloudinary = (await import('./cloudinaryConfig.js')).default;
    const fs = (await import('fs')).default;
    const uploadPromises = req.files.map(async (file) => {
      const imagePath = file.path;
      const result = await cloudinary.uploader.upload(imagePath, {
        folder: req.body.folderName || 'default-folder',
        use_filename: true,
        unique_filename: false,
        overwrite: true,
        transformation: [{ fetch_format: 'webp', quality: 'auto' }],
      });
      fs.unlinkSync(imagePath);
      return { success: true, url: result.secure_url, public_id: result.public_id, format: result.format };
    });
    const images = await Promise.all(uploadPromises);
    res.json({ success: true, images });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to upload image' });
  }
});

app.post('/upload-multiple', upload.array('images', 10), async (req, res) => {
  try {
    const cloudinary = (await import('./cloudinaryConfig.js')).default;
    const fs = (await import('fs')).default;
    const { folderName, storeId } = req.body;
    const uploadPromises = req.files.map(async (file) => {
      const imagePath = file.path;
      const result = await cloudinary.uploader.upload(imagePath, {
        folder: folderName || 'default-folder',
        use_filename: true,
        unique_filename: false,
      });
      const publicId = result.public_id;
      const imageName = publicId.split('/').pop();
      await cloudinary.uploader.upload(publicId, {
        type: 'upload',
        overwrite: true,
        transformation: [
          {
            overlay: { font_family: 'Arial', font_size: 30, text: '#' + imageName + ' @' + storeId },
            gravity: 'north',
            y: -30,
            x: 10,
          },
        ],
      });
      fs.unlinkSync(imagePath);
      return { success: true, url: result.secure_url, public_id: result.public_id, format: result.format };
    });
    const results = await Promise.all(uploadPromises);
    res.json(results);
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to upload images' });
  }
});

// =========================================================================
// MISC ENDPOINTS
// =========================================================================
app.get('/getUsers', (req, res) => {
  db.query('SELECT * from users order by userId asc', (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

app.get('/testing', (req, res) => res.json('this is testinggggggggggggg'));
app.get('/test', (req, res) => res.status(200).json({ message: 'Testing successfully....' }));

// =========================================================================
// NOTIFICATION JOB TRIGGER (legacy path)
// =========================================================================
app.post('/trigger-all-user-notifications', async (req, res) => {
  try {
    (async () => {
      try {
        await queryPromise('INSERT INTO job_logs (job_name, status, message) VALUES (?, ?, ?)', [
          'manual-all-user-notifications',
          'started',
          'Manual notification job started for all users.',
        ]);
        await sendDailyProductNotifications(true);
        await queryPromise('INSERT INTO job_logs (job_name, status, message) VALUES (?, ?, ?)', [
          'manual-all-user-notifications',
          'success',
          'Manual notification job completed for all users.',
        ]);
      } catch (err) {
        logger.error('[Manual] Push notifications error:', err.message);
        try {
          await queryPromise('INSERT INTO job_logs (job_name, status, message) VALUES (?, ?, ?)', [
            'manual-all-user-notifications',
            'failed',
            err.message,
          ]);
        } catch {}
      }
    })();
    res.status(202).json({ message: 'Notification process started.' });
  } catch (error) {
    res.status(500).json({ error: 'Error starting notification process.' });
  }
});

// =========================================================================
// CRON JOBS
// =========================================================================
cron.schedule('0 12 * * *', async () => {
  logger.info('[Cron] Noon trigger fired — starting daily ingest...');
  let jobLogId = null;
  try {
    const startResult = await queryPromise('INSERT INTO job_logs (job_name, status, message) VALUES (?, ?, ?)', [
      'daily-ingest',
      'started',
      'Daily noon ingest cron job triggered.',
    ]);
    jobLogId = startResult.insertId;
    const storeSummaries = await runDailyIngest(formatDataToJson, [], {
      extractionMode: process.env.INGEST_GEMINI_MODE || 'online',
    });
    await queryPromise('INSERT INTO job_logs (job_name, status, message) VALUES (?, ?, ?)', [
      'daily-ingest',
      'success',
      'Daily noon ingest completed successfully.',
    ]);
    if (jobLogId && Array.isArray(storeSummaries)) {
      for (const s of storeSummaries) {
        await queryPromise(
          'INSERT INTO ingest_store_logs (job_log_id, store_id, posts_fetched, images_discovered, images_uploaded, images_with_products, products_inserted, errors) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          [
            jobLogId,
            s.storeId,
            s.postsFetched,
            s.imagesDiscovered,
            s.imagesUploaded,
            s.imagesWithProducts,
            s.productsInserted,
            s.errors.length > 0 ? JSON.stringify(s.errors) : null,
          ],
        );
      }
    }
  } catch (err) {
    logger.error('[Cron] Daily ingest failed:', err.message);
    try {
      await queryPromise('INSERT INTO job_logs (job_name, status, message) VALUES (?, ?, ?)', [
        'daily-ingest',
        'failed',
        err.message,
      ]);
    } catch {}
  }
});
logger.info('[Cron] Daily noon ingest scheduler registered.');

cron.schedule('*/10 * * * *', async () => {
  try {
    const summary = await pollGeminiBatches({ limit: 20 });
    if (summary.processedBatches > 0 || summary.completedItems > 0 || summary.failedItems > 0) {
      logger.info(
        `[Cron] Gemini batch poll: scanned=${summary.scannedBatches}, processed=${summary.processedBatches}, completedItems=${summary.completedItems}, failedItems=${summary.failedItems}`,
      );
    }
  } catch (err) {
    logger.error('[Cron] Gemini batch poll failed:', err.message);
  }
});
logger.info('[Cron] Gemini batch poll scheduler registered (every 10 minutes).');

// =========================================================================
// SERVER START
// =========================================================================
const port = process.env.PORT || 3000;

async function checkGeminiModel() {
  try {
    const { GoogleGenAI } = await import('@google/genai');
    const aiStudio = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
    const result = await aiStudio.models.generateContent({
      model: 'gemini-2.5-flash-lite',
      contents: ['Reply with the single word: OK'],
    });
    logger.info(`Model check passed: "${result?.text?.trim()}"`);
  } catch (err) {
    logger.error(`Model check FAILED: ${err.message?.split('\n')[0] ?? err}`);
  }
}

async function initializeDatabaseTables() {
  try {
    await queryPromise(
      'CREATE TABLE IF NOT EXISTS `job_logs` (`id` INT NOT NULL AUTO_INCREMENT, `job_name` VARCHAR(100) NOT NULL, `status` VARCHAR(50) NOT NULL, `message` TEXT DEFAULT NULL, `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;',
    );
    logger.info('job_logs table initialized.');
    await queryPromise(
      'CREATE TABLE IF NOT EXISTS `ingest_store_logs` (`id` INT NOT NULL AUTO_INCREMENT, `job_log_id` INT NOT NULL, `store_id` INT NOT NULL, `posts_fetched` INT DEFAULT 0, `images_discovered` INT DEFAULT 0, `images_uploaded` INT DEFAULT 0, `images_with_products` INT DEFAULT 0, `products_inserted` INT DEFAULT 0, `errors` TEXT DEFAULT NULL, `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`id`), CONSTRAINT `fk_ingest_store_logs_job_logs` FOREIGN KEY (`job_log_id`) REFERENCES `job_logs` (`id`) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;',
    );
    logger.info('ingest_store_logs table initialized.');
    await queryPromise(
      'CREATE TABLE IF NOT EXISTS `broken_image_logs` (`id` INT NOT NULL AUTO_INCREMENT, `product_id` INT DEFAULT NULL, `store_id` INT DEFAULT NULL, `store_name` VARCHAR(150) DEFAULT NULL, `store_facebook_url` VARCHAR(255) DEFAULT NULL, `store_facebook_page_id` VARCHAR(100) DEFAULT NULL, `facebook_post_id` BIGINT DEFAULT NULL, `facebook_image_id` BIGINT DEFAULT NULL, `facebook_timestamp` TIMESTAMP NULL DEFAULT NULL, `raw_product_image_url` TEXT DEFAULT NULL, `attempted_cloudinary_url` TEXT DEFAULT NULL, `failing_url` TEXT DEFAULT NULL, `client_error` VARCHAR(100) DEFAULT NULL, `source_page` VARCHAR(100) DEFAULT NULL, `user_agent` VARCHAR(500) DEFAULT NULL, `extra_details` JSON DEFAULT NULL, `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`id`), KEY `idx_broken_image_logs_product_id` (`product_id`), KEY `idx_broken_image_logs_store_id` (`store_id`), KEY `idx_broken_image_logs_created_at` (`created_at`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;',
    );
    logger.info('broken_image_logs table initialized.');
    await queryPromise(
      'CREATE TABLE IF NOT EXISTS `ingest_gemini_batches` (`id` INT NOT NULL AUTO_INCREMENT, `store_id` INT NOT NULL, `provider_batch_name` VARCHAR(255) NOT NULL, `model_name` VARCHAR(100) NOT NULL, `status` VARCHAR(30) NOT NULL DEFAULT "pending", `run_label` VARCHAR(100) DEFAULT NULL, `total_items` INT NOT NULL DEFAULT 0, `completed_items` INT NOT NULL DEFAULT 0, `failed_items` INT NOT NULL DEFAULT 0, `error_message` TEXT DEFAULT NULL, `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP, `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, PRIMARY KEY (`id`), UNIQUE KEY `uniq_provider_batch_name` (`provider_batch_name`), KEY `idx_batch_status` (`status`), KEY `idx_batch_store` (`store_id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;',
    );
    logger.info('ingest_gemini_batches table initialized.');
    await queryPromise(
      'CREATE TABLE IF NOT EXISTS `ingest_gemini_batch_items` (`id` INT NOT NULL AUTO_INCREMENT, `batch_id` INT NOT NULL, `item_index` INT NOT NULL, `store_id` INT NOT NULL, `image_id` BIGINT DEFAULT NULL, `uploaded_url` TEXT DEFAULT NULL, `post_id` BIGINT DEFAULT NULL, `timestamp_unix` BIGINT DEFAULT NULL, `post_text` TEXT DEFAULT NULL, `flyer_book_id` VARCHAR(64) DEFAULT NULL, `user_id` INT DEFAULT NULL, `status` VARCHAR(30) NOT NULL DEFAULT "queued", `products_inserted` INT NOT NULL DEFAULT 0, `raw_response` MEDIUMTEXT DEFAULT NULL, `error_message` TEXT DEFAULT NULL, `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP, `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, PRIMARY KEY (`id`), KEY `idx_batch_items_batch_id` (`batch_id`), KEY `idx_batch_items_status` (`status`), CONSTRAINT `fk_ingest_gemini_batch_items_batch` FOREIGN KEY (`batch_id`) REFERENCES `ingest_gemini_batches` (`id`) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;',
    );
    logger.info('ingest_gemini_batch_items table initialized.');
    await queryPromise(
      'CREATE TABLE IF NOT EXISTS `ingest_rejected_products` (`id` BIGINT NOT NULL AUTO_INCREMENT, `source` VARCHAR(120) NOT NULL, `reason` VARCHAR(120) NOT NULL, `store_id` INT DEFAULT NULL, `user_id` INT DEFAULT NULL, `post_id` BIGINT DEFAULT NULL, `image_id` BIGINT DEFAULT NULL, `flyer_book_id` VARCHAR(64) DEFAULT NULL, `image_url` VARCHAR(2048) DEFAULT NULL, `product_description` VARCHAR(500) DEFAULT NULL, `old_price_raw` VARCHAR(64) DEFAULT NULL, `new_price_raw` VARCHAR(64) DEFAULT NULL, `sale_end_date_raw` VARCHAR(64) DEFAULT NULL, `raw_payload` JSON DEFAULT NULL, `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`id`), KEY `idx_rejected_created_at` (`created_at`), KEY `idx_rejected_reason` (`reason`), KEY `idx_rejected_store_id` (`store_id`), KEY `idx_rejected_image_id` (`image_id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;',
    );
    logger.info('ingest_rejected_products table initialized.');
  } catch (err) {
    logger.error('Failed to initialize tables:', err.message);
  }
}

app.listen(port, () => {
  logger.info(`Server is running on port ${port}`);
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        logger.info(`Server IP: http://${iface.address}:${port}`);
      }
    }
  }
  initializeDatabaseTables();
  checkGeminiModel();
});
