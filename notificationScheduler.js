import { Expo } from 'expo-server-sdk';
import { queryPromise } from './dbUtils.js';

/**
 * Finds users and on-sale products that match their favorite keywords,
 * excluding products they have already been notified about.
 * This function now relies on a consistent schema where all user foreign keys are INTs referencing users.id.
 */
async function getMatchingUsersAndProducts(frequency) {
  const query = `
    SELECT 
      u.id AS userId, -- The one and only user ID we need to use now
      p.productId,
      p.product_description
    FROM users u
    JOIN favorites f ON u.id = f.userId
    JOIN productkeywords pk_fav ON f.productId = pk_fav.productId
    JOIN productkeywords pk_sale ON pk_fav.keywordId = pk_sale.keywordId
    JOIN products p ON pk_sale.productId = p.productId
    WHERE 
      u.notification_frequency = ?
      AND p.sale_end_date >= CURDATE()
      AND NOT EXISTS (
        SELECT 1
        FROM sent_notifications sn
        WHERE sn.userId = u.id AND sn.productId = p.productId
      )
    GROUP BY u.id, p.productId, p.product_description;
  `;
  const matches = await queryPromise(query, [frequency]);
  return matches;
}

export async function sendDailyProductNotifications(forceAll = false) {
  const today = new Date();
  const dayOfWeek = today.getDay();
  const dayOfMonth = today.getDate();

  console.log(`[Push] Starting notification job. Forced: ${forceAll}`);

  let allMatches = [];
  if (forceAll) {
    const dailyMatches = await getMatchingUsersAndProducts('daily');
    const weeklyMatches = await getMatchingUsersAndProducts('weekly');
    const monthlyMatches = await getMatchingUsersAndProducts('monthly');
    allMatches = [...dailyMatches, ...weeklyMatches, ...monthlyMatches];
  } else {
    const dailyMatches = await getMatchingUsersAndProducts('daily');
    const weeklyMatches = (dayOfWeek === 0) ? await getMatchingUsersAndProducts('weekly') : [];
    const monthlyMatches = (dayOfMonth === 1) ? await getMatchingUsersAndProducts('monthly') : [];
    allMatches = [...dailyMatches, ...weeklyMatches, ...monthlyMatches];
  }

  if (allMatches.length === 0) {
    console.log('[Push] No new products matching user preferences today.');
    return;
  }

  // Group notifications by the consistent integer user ID.
  const userNotifications = allMatches.reduce((acc, match) => {
    const { userId, productId, product_description } = match;
    if (!acc[userId]) {
      acc[userId] = { productIds: new Set(), products: new Set() };
    }
    acc[userId].productIds.add(productId);
    acc[userId].products.add(product_description);
    return acc;
  }, {});

  const userIds = Object.keys(userNotifications).map(id => parseInt(id, 10));
  if (userIds.length === 0) {
    console.log('[Push] No users with matching products have push tokens.');
    return;
  }

  const tokenResults = await queryPromise('SELECT user_id, token FROM push_tokens WHERE user_id IN (?)', [userIds]);
  const userTokens = tokenResults.reduce((acc, row) => {
    if (!acc[row.user_id]) acc[row.user_id] = [];
    acc[row.user_id].push(row.token);
    return acc;
  }, {});

  const notifiedPairs = [];
  const messagesByProject = {};

  for (const userId of userIds) {
    const tokens = userTokens[userId];
    if (!tokens || tokens.length === 0) continue;

    const notificationData = userNotifications[userId];
    const productIds = Array.from(notificationData.productIds);
    const productDescriptions = Array.from(notificationData.products);
    const productCount = productIds.length;

    let body = `Ju keni ${productCount} produkte të reja në ofertë që ju pëlqejnë.`;
    if (productCount === 1) {
      body = `Ofertë e re për ${productDescriptions[0]}!`;
    } else if (productCount > 1) {
      body = `Ofertë për ${productDescriptions[0]} dhe ${productCount - 1} të tjera!`;
    }

    for (const pushToken of tokens) {
      if (!Expo.isExpoPushToken(pushToken)) continue;
      const projectId = pushToken.experienceId || '@flag81/my-flyers-app';
      if (!messagesByProject[projectId]) {
        messagesByProject[projectId] = [];
      }
      messagesByProject[projectId].push({
        to: pushToken,
        sound: 'default',
        title: '⭐ Oferta të Reja!',
        body: body,
        data: { screen: 'ProductsOnSale', productIds: productIds },
      });
    }

    productIds.forEach(productId => {
      notifiedPairs.push([userId, productId]);
    });
  }

  if (Object.keys(messagesByProject).length === 0) {
    console.log('[Push] No valid push tokens found for users with notifications.');
    return;
  }

  const expo = new Expo({ useFcmV1: true });
  for (const projectId in messagesByProject) {
    const projectMessages = messagesByProject[projectId];
    if (projectMessages.length > 0) {
      console.log(`[Push] Sending ${projectMessages.length} notifications for project ${projectId}...`);
      const chunks = expo.chunkPushNotifications(projectMessages);
      for (let chunk of chunks) {
        try {
          await expo.sendPushNotificationsAsync(chunk);
        } catch (error) {
          console.error(`[Push] Error sending notification chunk for project ${projectId}:`, error);
        }
      }
    }
  }

  if (notifiedPairs.length > 0) {
    try {
      const q = 'INSERT INTO sent_notifications (userId, productId) VALUES ?';
      await queryPromise(q, [notifiedPairs]);
      console.log(`[Push] Logged ${notifiedPairs.length} sent notifications.`);
    } catch (error) {
      console.error('[Push] Error logging sent notifications:', error);
    }
  }
  console.log('[Push] Finished sending notifications.');
}