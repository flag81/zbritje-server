import express from 'express';
import { queryPromise } from '../dbUtils.js';
import db from '../connection.js';

const router = express.Router();

router.get('/searchProducts', (req, res) => {
  const { keyword } = req.query;
  let q = `SELECT p.productId as productId, p.product_description as product_description, p.old_price as old_price, p.new_price as new_price, p.discount_percentage as discount_percentage, p.sale_end_date as sale_end_date, p.storeId as storeId, p.image_url as image_url, GROUP_CONCAT(k.keyword) AS keywords FROM products p LEFT JOIN productkeywords pk ON p.productId = pk.productId LEFT JOIN keywords k ON pk.keywordId = k.keywordId`;
  const queryParams = [];
  if (keyword) {
    const keywords = keyword.split(' ').map((kw) => kw.trim());
    const keywordConditions = keywords
      .filter((kw) => kw.length > 1)
      .map(() => `k.keyword LIKE ?`)
      .join(' OR ');
    q += ` WHERE ${keywordConditions}`;
    queryParams.push(...keywords.map((kw) => `%${kw}%`));
  }
  q += ` GROUP BY p.productId`;
  db.query(q, queryParams, (err, results) => {
    if (err) return res.status(500).json({ error: 'Failed to search products' });
    res.status(200).json(results);
  });
});

router.get('/getProductsWithKeywords', (req, res) => {
  const q = `SELECT p.productId, p.product_description, p.old_price, p.new_price, p.discount_percentage, p.sale_end_date, p.storeId, p.image_url, GROUP_CONCAT(k.keyword SEPARATOR ', ') AS keywords FROM products p LEFT JOIN productkeywords pk ON p.productId = pk.productId LEFT JOIN keywords k ON pk.keywordId = k.keywordId GROUP BY p.productId ORDER BY p.productId desc LIMIT 100`;
  db.query(q, (err, data) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch products with keywords' });
    return res.json(data);
  });
});

router.get('/getImagesByFlyerBookId', (req, res) => {
  const flyerBookId = req.query.flyerBookId;
  const q = `SELECT DISTINCT image_url FROM products WHERE flyer_book_id = ?`;
  db.query(q, [flyerBookId], (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

router.get('/products-by-ids', async (req, res) => {
  const { ids } = req.query;
  const userId = req.identifiedUser ? req.identifiedUser.userId : null;
  if (!ids) return res.status(400).json({ error: 'Product IDs are required.' });
  const productIds = ids
    .split(',')
    .map((id) => parseInt(id.trim(), 10))
    .filter(Number.isFinite);
  if (productIds.length === 0) return res.status(400).json({ error: 'No valid product IDs provided.' });
  try {
    const query = `SELECT p.*, f.userId IS NOT NULL AS isFavorite FROM products p LEFT JOIN favorites f ON p.productId = f.productId AND f.userId = ? WHERE p.productId IN (?)`;
    const products = await queryPromise(query, [userId, productIds]);
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch products.' });
  }
});

router.get('/isFavorite', async (req, res) => {
  const userId = req.identifiedUser?.id ?? req.identifiedUser?.userId ?? null;
  const productId = parseInt(req.query.productId, 10);
  const numericUserId =
    typeof userId === 'number'
      ? userId
      : typeof userId === 'string' && /^\d+$/.test(userId)
        ? parseInt(userId, 10)
        : null;
  if (!numericUserId || !Number.isFinite(productId) || productId <= 0)
    return res.status(200).json({ isFavorite: false });
  try {
    const result = await queryPromise(`SELECT 1 FROM favorites WHERE userId = ? AND productId = ? LIMIT 1`, [
      numericUserId,
      productId,
    ]);
    res.status(200).json({ isFavorite: result.length > 0 });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check favorite status' });
  }
});

export default router;
