import express from 'express';
import { identifyUserMiddleware } from '../middleware/authMiddleware.js';
import {
  subscribeWebPush,
  triggerAllWebPushNotifications,
  testPushNotification,
  triggerUserNotifications,
  triggerAllUserExpoNotifications,
} from '../services/notificationService.js';
import { registerPushToken } from '../controllers/notificationController.js';

const router = express.Router();

router.post('/subscribe-webpush', subscribeWebPush);
router.post('/trigger-all-webpush', triggerAllWebPushNotifications);
router.post('/register-push-token', identifyUserMiddleware, registerPushToken);
router.post('/test-push', testPushNotification);
router.post('/trigger-user-notifications', triggerUserNotifications);
router.post('/trigger-all-user-notifications', triggerAllUserExpoNotifications);

export default router;
