import { Expo } from 'expo-server-sdk';
import { queryPromise } from './dbUtils.js';

let expo = new Expo({
  useFcmV1: true
});

/**
 * Finds users and on-sale products that match their favorite keywords,
 * excluding products they have already been notified about.
 */
async function getMatchingUsersAndProducts(frequency) {
  const query = `
    WITH UserFavoriteKeywords AS (
      -- Find all unique keywords from a user's favorited products
      SELECT DISTINCT
        u.userId,
        k.keyword
      FROM users u
      JOIN favorites f ON u.userId = f.userId
      JOIN productkeywords pk ON f.productId = pk.productId
      JOIN keywords k ON pk.keywordId = k.keywordId
      WHERE u.notification_frequency = ?
    ),
    ProductsOnSale AS (
      -- Find all products currently on sale
      SELECT
        p.productId,
        p.product_description,
        k.keyword
      FROM products p
      JOIN productkeywords pk ON p.productId = pk.productId
      JOIN keywords k ON pk.keywordId = k.keywordId
      WHERE p.sale_end_date >= CURDATE()
    )
    -- Find users whose favorite keywords match an on-sale product
    -- and have NOT been notified about it before.
    SELECT
      ufk.userId,
      pos.productId,
      pos.product_description
    FROM UserFavoriteKeywords ufk
    JOIN ProductsOnSale pos ON ufk.keyword = pos.keyword
    WHERE NOT EXISTS (
      SELECT 1
      FROM sent_notifications sn
      WHERE sn.userId = ufk.userId AND sn.productId = pos.productId
    )
    GROUP BY ufk.userId, pos.productId, pos.product_description;
  `;


  console.log(`[Push] Fetching matching users and products for query: ${query}`);


  return await queryPromise(query, [frequency]);
}


export async function sendDailyProductNotifications() {
  const today = new Date();
  const dayOfWeek = today.getDay(); // 0 = Sunday
  const dayOfMonth = today.getDate(); // 1-31

  console.log('[Push] Starting daily notification job...');

  const dailyMatches = await getMatchingUsersAndProducts('daily');
  const weeklyMatches = (dayOfWeek === 0) ? await getMatchingUsersAndProducts('weekly') : [];
  const monthlyMatches = (dayOfMonth === 1) ? await getMatchingUsersAndProducts('monthly') : [];

  const allMatches = [...dailyMatches, ...weeklyMatches, ...monthlyMatches];

  if (allMatches.length === 0) {
    console.log('[Push] No new products matching user preferences today.');
    return;
  }

  // Group matching products by user
  const userNotifications = allMatches.reduce((acc, match) => {
    if (!acc[match.userId]) {
      acc[match.userId] = { products: [], productIds: [] };
    }
    if (!acc[match.userId].productIds.includes(match.productId)) {
        acc[match.userId].products.push(match.product_description);
        acc[match.userId].productIds.push(match.productId);
    }
    return acc;
  }, {});

  const userIds = Object.keys(userNotifications);
  const tokenResults = await queryPromise('SELECT user_id, token FROM push_tokens WHERE user_id IN (?)', [userIds]);
  
  const userTokens = tokenResults.reduce((acc, row) => {
    if (!acc[row.user_id]) acc[row.user_id] = [];
    acc[row.user_id].push(row.token);
    return acc;
  }, {});

  let messages = [];
  const notifiedPairs = []; // To store [userId, productId] for bulk insertion

  for (const userId of userIds) {
    const tokens = userTokens[userId];
    if (!tokens || tokens.length === 0) continue;

    const notificationData = userNotifications[userId];
    const productCount = notificationData.productIds.length;
    const body = `Ju keni ${productCount} produkte të reja në ofertë që ju pëlqejnë.`;

    for (const pushToken of tokens) {
      if (!Expo.isExpoPushToken(pushToken)) continue;
      messages.push({
        to: pushToken,
        sound: 'default',
        title: '⭐ Oferta të Reja!',
        body: body,
        data: { screen: 'ProductsOnSale', productIds: notificationData.productIds },
      });
    }
    notificationData.productIds.forEach(productId => {
        notifiedPairs.push([userId, productId]);
    });
  }

  if (messages.length === 0) {
    console.log('[Push] No valid push tokens for the matched users.');
    return;
  }

  let chunks = expo.chunkPushNotifications(messages);
  for (let chunk of chunks) {
    try {
      await expo.sendPushNotificationsAsync(chunk);
    } catch (error) {
      console.error('[Push] Error sending notification chunk:', error);
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