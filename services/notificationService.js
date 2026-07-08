import { Expo } from 'expo-server-sdk';
import webPushPkg from 'web-push';
import { queryPromise } from '../dbUtils.js';
import db from '../connection.js';
import logger from './logger.js';

const webPush = webPushPkg && webPushPkg.default ? webPushPkg.default : webPushPkg;

const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;
const vapidAdminEmail = process.env.VAPID_ADMIN_EMAIL || 'admin@example.com';
export const webPushEnabled = Boolean(vapidPublicKey && vapidPrivateKey);

if (webPushEnabled) {
  webPush.setVapidDetails(`mailto:${vapidAdminEmail}`, vapidPublicKey, vapidPrivateKey);
  logger.info('Web push VAPID configured');
} else {
  logger.warn('Web push disabled: missing VAPID keys');
}

export async function subscribeWebPush(req, res) {
  if (!webPushEnabled) {
    return res.status(503).json({ error: 'Web push is not configured on the server (missing VAPID keys).' });
  }
  try {
    const { subscription, userId } = req.body;
    if (!subscription || !subscription.endpoint) return res.status(400).json({ error: 'Invalid subscription' });
    const q = `INSERT INTO subscriptions (endpoint, subscription, userId) VALUES (?, ?, ?)
               ON DUPLICATE KEY UPDATE subscription = ?`;
    db.query(
      q,
      [subscription.endpoint, JSON.stringify(subscription), userId || null, JSON.stringify(subscription)],
      (err) => {
        if (err) {
          logger.error('DB save subscription error:', err);
          return res.status(500).json({ error: 'DB error' });
        }
        res.json({ success: true });
      },
    );
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Server error' });
  }
}

export async function triggerAllWebPushNotifications(req, res) {
  if (!webPushEnabled) {
    return res.status(503).json({ error: 'Web push is not configured on the server (missing VAPID keys).' });
  }
  try {
    const q = `SELECT subscription FROM subscriptions`;
    db.query(q, async (err, results) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      const payload = {
        title: req.body.title || 'Meniven',
        body: req.body.body || 'Notification from server',
        icon: req.body.icon || '/icon.png',
        url: req.body.url || process.env.FRONTEND_URL || '/',
      };
      const sendPromises = results.map((row) => {
        const sub = JSON.parse(row.subscription);
        return webPush.sendNotification(sub, JSON.stringify(payload)).catch((e) => {
          logger.error('sendNotification error:', e);
        });
      });
      await Promise.all(sendPromises);
      res.json({ success: true, sent: results.length });
    });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Server error' });
  }
}

export async function testPushNotification(req, res) {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'User ID is required.' });

  try {
    const tokenResults = await queryPromise('SELECT token FROM push_tokens WHERE user_id = ?', [userId]);
    if (tokenResults.length === 0) return res.status(404).json({ message: 'No push tokens found for this user.' });

    const tokens = tokenResults.map((row) => row.token);
    const messages = [];
    for (const pushToken of tokens) {
      if (!Expo.isExpoPushToken(pushToken)) continue;
      messages.push({
        to: pushToken,
        sound: 'default',
        title: 'Test Njoftimi',
        body: `Ky eshte nje test nga serveri per User ID: ${userId}`,
        data: { withSome: 'data' },
      });
    }

    if (messages.length === 0) return res.status(400).json({ message: 'No valid Expo push tokens found.' });

    const expo = new Expo({ useFcmV1: true });
    const chunks = expo.chunkPushNotifications(messages);
    for (const chunk of chunks) {
      await expo.sendPushNotificationsAsync(chunk);
    }
    res.status(200).json({ message: 'Test notification sent.' });
  } catch (error) {
    logger.error('[Push Test] Error:', error);
    res.status(500).json({ error: 'Failed to process test notification.' });
  }
}

export async function triggerUserNotifications(req, res) {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'User ID is required.' });

  try {
    const matchingProductsQuery = `
      WITH UserFavoriteKeywords AS (
        SELECT DISTINCT k.keyword
        FROM favorites f
        JOIN productkeywords pk ON f.productId = pk.productId
        JOIN keywords k ON pk.keywordId = k.keywordId
        WHERE f.userId = ?
      ),
      ProductsOnSale AS (
        SELECT p.productId, p.product_description, k.keyword
        FROM products p
        JOIN productkeywords pk ON p.productId = pk.productId
        JOIN keywords k ON pk.keywordId = k.keywordId
        WHERE p.sale_end_date >= CURDATE()
      )
      SELECT DISTINCT pos.productId
      FROM UserFavoriteKeywords ufk
      JOIN ProductsOnSale pos ON ufk.keyword = pos.keyword;
    `;
    const matchingProducts = await queryPromise(matchingProductsQuery, [userId]);
    if (matchingProducts.length === 0) {
      return res.status(200).json({ message: 'Nuk u gjetën produkte në ofertë që përputhen me preferencat tuaja.' });
    }

    const tokenResults = await queryPromise('SELECT token FROM push_tokens WHERE user_id = ?', [userId]);
    if (tokenResults.length === 0) {
      return res.status(404).json({ message: 'Përdoruesi nuk ka shenja njoftimi të regjistruara.' });
    }
    const tokens = tokenResults.map((row) => row.token);

    const productIds = matchingProducts.map((p) => p.productId);
    const productCount = productIds.length;
    const body = `Ju keni ${productCount} produkte në ofertë që përputhen me preferencat tuaja.`;

    const messages = [];
    for (const pushToken of tokens) {
      if (!Expo.isExpoPushToken(pushToken)) continue;
      messages.push({
        to: pushToken,
        sound: 'default',
        title: 'Oferta të Përshtatura për Ju!',
        body,
        data: { screen: 'ProductsOnSale', productIds },
      });
    }

    if (messages.length === 0) return res.status(400).json({ message: 'Nuk u gjetën shenja të vlefshme njoftimi.' });

    const expo = new Expo({ useFcmV1: true });
    const chunks = expo.chunkPushNotifications(messages);
    for (const chunk of chunks) {
      await expo.sendPushNotificationsAsync(chunk);
    }

    return res.status(200).json({ message: `Njoftimi u dërgua me sukses për ${productCount} produkte.` });
  } catch (error) {
    logger.error(`[triggerUserNotifications] Error:`, error);
    return res.status(500).json({ error: 'Gabim në server gjatë dërgimit të njoftimit.' });
  }
}

export async function triggerAllUserExpoNotifications(req, res) {
  try {
    (async () => {
      try {
        const { sendDailyProductNotifications } = await import('../notificationScheduler.js');
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
        logger.error('[Manual] Push notifications job error:', err.message);
        try {
          await queryPromise('INSERT INTO job_logs (job_name, status, message) VALUES (?, ?, ?)', [
            'manual-all-user-notifications',
            'failed',
            err.message,
          ]);
        } catch (dbErr) {
          logger.error('[Manual] Failed to log push notification failure:', dbErr.message);
        }
      }
    })();
    res.status(202).json({ message: 'Procesi i dërgimit të njoftimeve ka filluar.' });
  } catch (error) {
    logger.error('[Manual Trigger] Error starting notification job:', error);
    res.status(500).json({ error: 'Gabim gjatë fillimit të procesit të njoftimeve.' });
  }
}
