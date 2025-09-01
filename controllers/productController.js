import { queryPromise } from '../dbUtils.js'; // Assuming dbUtils.js exports queryPromise

/**
 * GET /products - For the mobile app
 * Fetches products with filtering, pagination, and favorite status for a specific user.
 */
export const getProducts = async (req, res) => {
  const userId = req.identifiedUser ? req.identifiedUser.id : null;
  let storeId = parseInt(req.query.storeId, 10);
  const isFavoriteQueryParam = req.query.isFavorite === 'true';
  const onSale = req.query.onSale === 'true';
  const keywordQuery = req.query.keyword || null;
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const offset = (page - 1) * limit;
  const today = new Date().toISOString().split('T')[0];

  if (isNaN(storeId) || storeId <= 0) {
    storeId = null;
  }

  const searchKeywordsArray = keywordQuery ? keywordQuery.split(' ').map(kw => kw.trim()).filter(kw => kw.length > 1) : [];
  let matchedKeywordCountSelectSQL = '0 AS matched_keyword_count';
  if (searchKeywordsArray.length > 0) {
    const keywordCases = searchKeywordsArray.map(() => `WHEN ? THEN 1`).join(' ');
    matchedKeywordCountSelectSQL = `(
      SELECT COUNT(DISTINCT k.keyword)
      FROM productkeywords pk
      JOIN keywords k ON pk.keywordId = k.keywordId
      WHERE pk.productId = p.productId AND k.keyword IN (${searchKeywordsArray.map(() => '?').join(',')})
    ) AS matched_keyword_count`;
  }

  let q = `
    SELECT
      p.*,
      s.storeName,
      ${userId ? 'f.userId IS NOT NULL AS isFavorite,' : '0 AS isFavorite,'}
      p.sale_end_date >= CURDATE() AS productOnSale,
      ${matchedKeywordCountSelectSQL}
    FROM
      products p
    JOIN
      stores s ON p.storeId = s.storeId
    ${userId ? 'LEFT JOIN favorites f ON p.productId = f.productId AND f.userId = ?' : ''}
  `;

  const params = [];
  if (userId) {
    params.push(userId);
  }
  if (searchKeywordsArray.length > 0) {
    params.push(...searchKeywordsArray);
  }

  const conditions = [];
  if (storeId) {
    conditions.push('p.storeId = ?');
    params.push(storeId);
  }
  if (isFavoriteQueryParam) {
    if (!userId) {
      return res.json({ data: [], nextPage: null });
    }
    conditions.push('f.userId IS NOT NULL');
  }
  if (onSale) {
    conditions.push('p.sale_end_date >= ?');
    params.push(today);
  }
  if (searchKeywordsArray.length > 0) {
    conditions.push(`
      EXISTS (
        SELECT 1
        FROM productkeywords pk
        JOIN keywords k ON pk.keywordId = k.keywordId
        WHERE pk.productId = p.productId AND k.keyword IN (${searchKeywordsArray.map(() => '?').join(',')})
      )
    `);
    params.push(...searchKeywordsArray);
  }

  if (conditions.length > 0) {
    q += ' WHERE ' + conditions.join(' AND ');
  }

  q += `
    GROUP BY p.productId
    ORDER BY productOnSale DESC, isFavorite DESC, matched_keyword_count DESC, p.productId DESC
    LIMIT ? OFFSET ?
  `;
  params.push(limit, offset);

  try {
    const data = await queryPromise(q, params);
    const nextPage = data.length === limit ? page + 1 : null;
    res.json({ data, nextPage });
  } catch (err) {
    console.error("getProducts error:", err);
    res.status(500).json({ error: "Failed to retrieve products" });
  }
};

/**
 * GET /products/dashboard - For the web dashboard
 * Fetches products with different filtering for admin purposes.
 */
export const getProductsDashboard = async (req, res) => {
  const userId = parseInt(req.query.userId, 10) || null;
  let storeId = parseInt(req.query.storeId, 10);
  const isFavorite = req.query.isFavorite || null;
  const onSale = req.query.onSale || null;
  const keyword = req.query.keyword || null;
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const offset = (page - 1) * limit;
  const today = new Date().toISOString().split('T')[0];

  if (isNaN(storeId) || storeId <= 0) {
    storeId = null;
  }

  let q = `
    SELECT p.*, s.storeName, GROUP_CONCAT(k.keyword) as keywords
    FROM products p
    LEFT JOIN stores s ON p.storeId = s.storeId
    LEFT JOIN productkeywords pk ON p.productId = pk.productId
    LEFT JOIN keywords k ON pk.keywordId = k.keywordId
  `;
  const conditions = [];
  const params = [];

  if (storeId) {
    conditions.push('p.storeId = ?');
    params.push(storeId);
  }
  if (onSale === 'true') {
    conditions.push('p.sale_end_date >= ?');
    params.push(today);
  } else if (onSale === 'false') {
    conditions.push('p.sale_end_date < ?');
    params.push(today);
  }
  if (keyword) {
    conditions.push('(p.product_description LIKE ? OR k.keyword LIKE ?)');
    params.push(`%${keyword}%`, `%${keyword}%`);
  }

  if (conditions.length > 0) {
    q += ' WHERE ' + conditions.join(' AND ');
  }

  q += ' GROUP BY p.productId ORDER BY p.productId DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  try {
    const data = await queryPromise(q, params);
    const nextPage = data.length === limit ? page + 1 : null;
    res.json({ data, nextPage });
  } catch (err) {
    console.error("getProductsDashboard error:", err);
    res.status(500).json({ error: "Failed to retrieve products for dashboard" });
  }
};

/**
 * DELETE /products/:productId
 * Deletes a product and its associated keywords.
 */
export const deleteProduct = async (req, res) => {
  const { productId } = req.params;
  try {
    await queryPromise('START TRANSACTION');
    await queryPromise('DELETE FROM productkeywords WHERE productId = ?', [productId]);
    await queryPromise('DELETE FROM favorites WHERE productId = ?', [productId]);
    await queryPromise('DELETE FROM sent_notifications WHERE productId = ?', [productId]);
    await queryPromise('DELETE FROM products WHERE productId = ?', [productId]);
    await queryPromise('COMMIT');
    res.status(200).json({ message: 'Product and related data deleted successfully.' });
  } catch (error) {
    await queryPromise('ROLLBACK');
    console.error('Error deleting product:', error);
    res.status(500).json({ message: 'An error occurred while deleting the product.' });
  }
};

/**
 * PUT /products/:productId/prices
 * Updates the prices of a single product.
 */
export const updateProductPrices = async (req, res) => {
  const { productId } = req.params;
  const { oldPrice, newPrice } = req.body;
  try {
    const q = 'UPDATE products SET old_price = ?, new_price = ? WHERE productId = ?';
    await queryPromise(q, [oldPrice, newPrice, productId]);
    res.status(200).json({ message: 'Product prices updated successfully.' });
  } catch (error) {
    console.error('Error updating product prices:', error);
    res.status(500).json({ error: 'Failed to update product prices.' });
  }
};

/**
 * PUT /products/:productId/description
 * Updates the description of a single product.
 */
export const editProductDescription = async (req, res) => {
  const { productId } = req.params;
  const { description } = req.body;
  try {
    const q = 'UPDATE products SET product_description = ? WHERE productId = ?';
    await queryPromise(q, [description, productId]);
    res.status(200).json({ message: 'Product description updated successfully.' });
  } catch (error) {
    console.error('Error updating product description:', error);
    res.status(500).json({ error: 'Failed to update product description.' });
  }
};

/**
 * POST /products/:productId/keywords
 * Adds a keyword to a product.
 */
export const addKeyword = async (req, res) => {
    const { productId } = req.params;
    const { keyword } = req.body;

    if (!keyword || keyword.trim() === '') {
        return res.status(400).json({ error: 'Keyword cannot be empty.' });
    }

    try {
        await queryPromise('START TRANSACTION');
        
        let keywordResults = await queryPromise('SELECT keywordId FROM keywords WHERE keyword = ?', [keyword]);
        let keywordId;

        if (keywordResults.length > 0) {
            keywordId = keywordResults[0].keywordId;
        } else {
            const insertResult = await queryPromise('INSERT INTO keywords (keyword) VALUES (?)', [keyword]);
            keywordId = insertResult.insertId;
        }

        await queryPromise('INSERT IGNORE INTO productkeywords (productId, keywordId) VALUES (?, ?)', [productId, keywordId]);
        
        await queryPromise('COMMIT');
        res.status(201).json({ message: 'Keyword added successfully.' });
    } catch (error) {
        await queryPromise('ROLLBACK');
        console.error('Error adding keyword:', error);
        res.status(500).json({ error: 'Failed to add keyword.' });
    }
};

/**
 * DELETE /products/:productId/keywords
 * Removes a keyword from a product.
 */
export const removeKeyword = async (req, res) => {
    const { productId } = req.params;
    const { keyword } = req.body;

    if (!keyword) {
        return res.status(400).json({ error: 'Keyword is required.' });
    }

    try {
        const q = `
            DELETE pk FROM productkeywords pk
            JOIN keywords k ON pk.keywordId = k.keywordId
            WHERE pk.productId = ? AND k.keyword = ?
        `;
        const result = await queryPromise(q, [productId, keyword]);
        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Keyword removed successfully.' });
        } else {
            res.status(404).json({ message: 'Keyword not found for this product.' });
        }
    } catch (error) {
        console.error('Error removing keyword:', error);
        res.status(500).json({ error: 'Failed to remove keyword.' });
    }
};

/**
 * POST /products/:productId/favorite
 * Adds a product to the user's favorites.
 */
export const addFavorite = async (req, res) => {
    const { productId } = req.params;
    const userId = req.identifiedUser.id; // From middleware

    try {
        await queryPromise('INSERT INTO favorites (userId, productId) VALUES (?, ?)', [userId, productId]);
        res.status(201).json({ message: 'Product added to favorites.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(200).json({ message: 'Product is already in favorites.' });
        }
        console.error('Error adding favorite:', error);
        res.status(500).json({ error: 'Failed to add favorite.' });
    }
};

/**
 * DELETE /products/:productId/favorite
 * Removes a product from the user's favorites.
 */
export const removeFavorite = async (req, res) => {
    const { productId } = req.params;
    const userId = req.identifiedUser.id; // From middleware

    try {
        await queryPromise('DELETE FROM favorites WHERE userId = ? AND productId = ?', [userId, productId]);
        res.status(200).json({ message: 'Product removed from favorites.' });
    } catch (error) {
        console.error('Error removing favorite:', error);
        res.status(500).json({ error: 'Failed to remove favorite.' });
    }
};

/**
 * POST /products/batch - Internal function to insert multiple products
 * This is called by the flyerController after data extraction.
 */
export const insertProducts = async (products) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    let insertedCount = 0;

    for (const product of products) {
      const { product_description, old_price, new_price, discount_percentage, sale_end_date, storeId, keywords, image_url, category_id, flyer_book_id, postId, imageId, timestamp } = product;

      // Data validation and sanitization
      const oldPriceNumber = parseFloat(old_price) || 0;
      const newPriceNumber = parseFloat(new_price) || 0;
      const formattedTimestamp = new Date(timestamp).toISOString().slice(0, 19).replace('T', ' ');

      const [productResult] = await connection.query(
        `INSERT INTO products (product_description, old_price, new_price, discount_percentage, sale_end_date, storeId, image_url, category_id, flyer_book_id, postId, imageId, timestamp)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [product_description, oldPriceNumber, newPriceNumber, discount_percentage, sale_end_date, storeId, image_url, category_id, flyer_book_id, postId, imageId, formattedTimestamp]
      );
      
      const productId = productResult.insertId;
      insertedCount++;

      if (keywords && Array.isArray(keywords)) {
        for (const keyword of keywords) {
          const [keywordRows] = await connection.query('SELECT keywordId FROM keywords WHERE keyword = ?', [keyword]);
          let keywordId;
          if (keywordRows.length > 0) {
            keywordId = keywordRows[0].keywordId;
          } else {
            const [newKeyword] = await connection.query('INSERT INTO keywords (keyword) VALUES (?)', [keyword]);
            keywordId = newKeyword.insertId;
          }
          await connection.query('INSERT IGNORE INTO productkeywords (productId, keywordId) VALUES (?, ?)', [productId, keywordId]);
        }
      }
    }

    await connection.commit();
    return { insertedCount, message: "Batch insert successful." };
  } catch (error) {
    await connection.rollback();
    console.error('[ProductController] Batch insert failed:', error);
    throw error; // Re-throw to be caught by the calling controller
  } finally {
    connection.release();
  }
};