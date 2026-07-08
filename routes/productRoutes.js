import express from 'express';
import { identifyUserMiddleware } from '../middleware/authMiddleware.js';
import { queryPromise } from '../dbUtils.js';
import db from '../connection.js';
import logger from '../services/logger.js';

const router = express.Router();

router.get('/', identifyUserMiddleware, async (req, res) => {
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
    const descriptionConditions = searchKeywordsArray.map(() => `p.product_description LIKE ?`).join(' OR ');
    conditions.push(`((${keywordTableConditions}) OR (${descriptionConditions}))`);
    searchKeywordsArray.forEach((kw) => whereParams.push(`${kw}%`));
    searchKeywordsArray.forEach((kw) => whereParams.push(`${kw}%`));
  }

  if (conditions.length > 0) q += ' WHERE ' + conditions.join(' AND ');

  q += ` GROUP BY p.productId ORDER BY matched_keyword_count DESC, productOnSale DESC, categoryWeight DESC, p.productId DESC LIMIT ? OFFSET ?`;

  const finalParams = [...selectParams, ...whereParams, limit, offset];

  try {
    const data = await queryPromise(q, finalParams);
    const nextPage = data.length === limit ? page + 1 : null;
    return res.json({ data, nextPage });
  } catch (err) {
    logger.info('getProducts error:', err);
    return res.status(500).json({ error: 'Failed to retrieve products' });
  }
});

router.get('/dashboard', async (req, res) => {
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
    conditions.push(`p.storeId = ?`);
    params.push(storeId);
  }
  if (isFavorite && isFavorite.trim() === 'true') {
    conditions.push(`f.userId = ?`);
    params.push(userId);
  }
  if (onSale === 'true') {
    conditions.push(`p.sale_end_date >= ?`);
    params.push(today);
  }
  if (keyword) {
    const keywords = keyword.split(' ').map((kw) => kw.trim());
    const keywordConditions = keywords
      .filter((kw) => kw.length > 1)
      .map(() => `k.keyword LIKE ?`)
      .join(' OR ');
    if (keywordConditions.length > 0) {
      conditions.push(`(${keywordConditions})`);
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

router.delete('/:productId', async (req, res) => {
  const productId = req.params.productId;
  const dbQuery = (query, params) =>
    new Promise((resolve, reject) => {
      db.query(query, params, (err, result) => {
        if (err) return reject(err);
        resolve(result);
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

router.put('/:productId/prices', (req, res) => {
  const { productId } = req.params;
  const { oldPrice, newPrice } = req.body;
  const q = `UPDATE products SET old_price = ?, new_price = ? WHERE productId = ?`;
  db.query(q, [oldPrice, newPrice, productId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update product prices' });
    res.status(200).json({ message: 'Product prices updated successfully' });
  });
});

router.put('/:productId/description', (req, res) => {
  const { productId } = req.params;
  const { newDescription } = req.body;
  const q = `UPDATE products SET product_description = ? WHERE productId = ?`;
  db.query(q, [newDescription, productId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update product description' });
    res.status(200).json({ message: 'Product description updated successfully' });
  });
});

router.put('/:productId/sale-date', (req, res) => {
  const { productId } = req.params;
  const { sale_end_date } = req.body;
  const date = new Date(sale_end_date);
  const formattedDate = date.toISOString().slice(0, 19).replace('T', ' ');
  const q = `UPDATE products SET sale_end_date = ? WHERE productId = ?`;
  db.query(q, [formattedDate, productId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update product date' });
    res.status(200).json({ message: 'Product date updated successfully' });
  });
});

router.put('/:productId/store', (req, res) => {
  const { productId } = req.params;
  const { storeId } = req.body;
  const q = `UPDATE products SET storeId = ? WHERE productId = ?`;
  db.query(q, [storeId, productId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update store' });
    res.status(200).json({ message: 'Store updated successfully' });
  });
});

router.post('/:productId/keywords', (req, res) => {
  const { productId } = req.params;
  const { keyword } = req.body;
  const q = `INSERT INTO keywords (keyword) VALUES (?) ON DUPLICATE KEY UPDATE keywordId = LAST_INSERT_ID(keywordId)`;
  db.query(q, [keyword], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to add keyword' });
    const keywordId = result.insertId;
    db.query(`INSERT INTO productkeywords (productId, keywordId) VALUES (?, ?)`, [productId, keywordId], (err) => {
      if (err) return res.status(500).json({ error: 'Failed to add keyword to product' });
      res.status(200).json({ message: 'Keyword added successfully' });
    });
  });
});

router.delete('/:productId/keywords', (req, res) => {
  const { productId } = req.params;
  const { keyword } = req.body;
  db.query(`SELECT keywordId FROM keywords WHERE keyword = ?`, [keyword], (err, result) => {
    if (err) return res.status(500).json({ error: 'Failed to get keywordId' });
    const keywordId = result[0]?.keywordId;
    db.query(`DELETE FROM productkeywords WHERE productId = ? AND keywordId = ?`, [productId, keywordId], (err) => {
      if (err) return res.status(500).json({ error: 'Failed to remove keyword from product' });
      res.status(200).json({ message: 'Keyword removed successfully' });
    });
  });
});

router.post('/:productId/favorite', identifyUserMiddleware, async (req, res) => {
  const { productId } = req.params;
  if (!req.identifiedUser || !req.identifiedUser.userId)
    return res.status(401).json({ error: 'User identification required.' });

  const tokenUserId = req.identifiedUser?.userId ?? null;
  const userId = req.identifiedUser?.id ?? tokenUserId ?? null;
  let numericUserId =
    typeof userId === 'number'
      ? userId
      : typeof userId === 'string' && /^\d+$/.test(userId)
        ? parseInt(userId, 10)
        : null;

  if (!numericUserId && typeof tokenUserId === 'string' && tokenUserId.trim() !== '') {
    try {
      const existing = await queryPromise('SELECT id FROM users WHERE userId = ? ORDER BY id DESC LIMIT 1', [
        tokenUserId,
      ]);
      if (Array.isArray(existing) && existing[0]?.id) {
        numericUserId = existing[0].id;
      } else {
        await queryPromise('INSERT INTO users (userId, is_registered, `timestamp`) VALUES (?, ?, NOW())', [
          tokenUserId,
          false,
        ]);
        const created = await queryPromise('SELECT id FROM users WHERE userId = ? ORDER BY id DESC LIMIT 1', [
          tokenUserId,
        ]);
        if (Array.isArray(created) && created[0]?.id) numericUserId = created[0].id;
      }
    } catch (resolveErr) {
      logger.error('Failed to resolve numeric user id:', resolveErr);
    }
  }

  if (!numericUserId) return res.status(401).json({ error: 'Could not resolve numeric user id.' });
  const productIdNum = parseInt(productId, 10);
  if (!Number.isFinite(productIdNum) || productIdNum <= 0)
    return res.status(400).json({ error: 'Valid Product ID is required.' });

  const q = `INSERT INTO favorites (userId, productId) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM favorites WHERE userId = ? AND productId = ?)`;
  try {
    const result = await queryPromise(q, [numericUserId, productIdNum, numericUserId, productIdNum]);
    const added = Boolean(result?.affectedRows);
    res.status(200).json({ message: added ? 'Favorite added successfully' : 'Favorite already exists', added });
  } catch (err) {
    logger.error('Error adding favorite:', err);
    return res.status(500).json({ error: 'Failed to add favorite' });
  }
});

router.delete('/:productId/favorite', identifyUserMiddleware, async (req, res) => {
  const { productId } = req.params;
  if (!req.identifiedUser || !req.identifiedUser.userId)
    return res.status(401).json({ error: 'User identification required.' });
  const userId = req.identifiedUser?.id ?? req.identifiedUser?.userId ?? null;
  const numericUserId =
    typeof userId === 'number'
      ? userId
      : typeof userId === 'string' && /^\d+$/.test(userId)
        ? parseInt(userId, 10)
        : null;
  if (!numericUserId) return res.status(401).json({ error: 'User identification required.' });
  const q = `DELETE FROM favorites WHERE userId = ? AND productId = ?`;
  try {
    await queryPromise(q, [numericUserId, parseInt(productId, 10)]);
    res.status(200).json({ message: 'Favorite removed successfully' });
  } catch (err) {
    logger.error('Error removing favorite:', err);
    return res.status(500).json({ error: 'Failed to remove favorite' });
  }
});

export default router;
