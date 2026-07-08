import {
  subscribeWebPush,
  testPushNotification,
  triggerUserNotifications,
  triggerAllUserExpoNotifications,
} from '../services/notificationService.js';
import { queryPromise } from '../dbUtils.js';
import logger from '../services/logger.js';

export { subscribeWebPush, testPushNotification, triggerUserNotifications };

export const registerPushToken = async (req, res) => {
  const { token } = req.body;
  const userId = req.identifiedUser?.userId;
  if (!userId || !token) {
    return res.status(400).json({ error: 'User ID and token are required.' });
  }
  try {
    const q =
      'INSERT INTO push_tokens (user_id, token) VALUES (?, ?) ON DUPLICATE KEY UPDATE user_id = VALUES(user_id)';
    await queryPromise(q, [userId, token]);
    res.status(200).json({ message: 'Token registered successfully.' });
  } catch (err) {
    logger.error('[Push] Error registering token:', err);
    res.status(500).json({ error: 'Failed to register token.' });
  }
};

export { triggerAllUserExpoNotifications };
