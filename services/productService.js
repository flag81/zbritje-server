import db from '../connection.js';
import { queryPromise } from '../dbUtils.js';
import JSON5 from 'json5';

const allMessages = [];

export { allMessages };

export function salvageProductsFromTruncatedJsonArray(rawText) {
  if (!rawText || typeof rawText !== 'string') return [];
  const normalized = rawText.trim();
  const startIdx = normalized.indexOf('[');
  if (startIdx === -1) return [];
  const body = normalized.slice(startIdx + 1);
  const objects = [];
  let depth = 0;
  let inString = false;
  let escaped = false;
  let objStart = -1;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === '{') {
      if (depth === 0) objStart = i;
      depth += 1;
      continue;
    }
    if (ch === '}') {
      if (depth > 0) depth -= 1;
      if (depth === 0 && objStart !== -1) {
        const objText = body.slice(objStart, i + 1);
        try {
          const parsed = JSON5.parse(objText);
          if (parsed && typeof parsed === 'object') objects.push(parsed);
        } catch {}
        objStart = -1;
      }
    }
  }
  return objects;
}

async function dbQuery(query, params) {
  return new Promise((resolve, reject) => {
    db.query(query, params, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    });
  });
}

export async function insertProducts1(jsonData) {
  const products = Array.isArray(jsonData) ? jsonData : JSON5.parse(jsonData);
  if (!Array.isArray(products)) return;
  if (products.length === 0) return;

  const normalizationResults = products.map((product) => normalizeProductForInsert(product));
  const normalizedProducts = normalizationResults.filter((result) => result.normalized).map((result) => result.normalized);
  const rejectedProducts = normalizationResults
    .filter((result) => !result.normalized)
    .map((result) => ({ source: 'insertProducts1', reason: result.reason, product: result.original }));

  if (rejectedProducts.length > 0) {
    try {
      await logRejectedProducts(rejectedProducts);
    } catch (logErr) {
      allMessages.push(`Warning: failed to log rejected products: ${logErr.message}`);
    }
  }

  if (normalizedProducts.length === 0) {
    allMessages.push('No valid offer products to insert (skipped invalid/non-priced entries).');
    return;
  }

  try {
    await dbQuery('START TRANSACTION');
    for (const product of normalizedProducts) {
      const {
        product_description,
        old_price,
        new_price,
        discount_percentage,
        sale_end_date,
        storeId,
        keywords,
        image_url,
        category_id,
        flyer_book_id,
        postId,
        imageId,
        timestamp,
      } = product;

      const oldPriceNumber = old_price || 0;
      const newPriceNumber = new_price || 0;
      const numericImageId = parseInt(imageId, 10);
      if (isNaN(numericImageId)) throw new Error(`Invalid numeric value for imageId: ${imageId}`);

      let numericFlyerBookId = null;
      if (flyer_book_id !== undefined && flyer_book_id !== null) {
        const strVal = String(flyer_book_id);
        const parts = strVal.split('-');
        const targetValue = parts.length > 1 ? parts[1] : parts[0];
        const parsed = parseInt(targetValue, 10);
        if (!isNaN(parsed)) {
          numericFlyerBookId = parsed > 2147483647 ? parsed % 1000000000 : parsed;
        }
      }

      const dateObject = new Date(timestamp);
      const formattedTimestamp = dateObject.toISOString().slice(0, 19).replace('T', ' ');

      const productResult = await dbQuery(
        `INSERT INTO products (product_description, old_price, new_price, discount_percentage, sale_end_date, storeId, image_url, category_id, flyer_book_id, postId, imageId, timestamp)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          product_description,
          oldPriceNumber,
          newPriceNumber,
          discount_percentage,
          sale_end_date,
          storeId,
          image_url,
          category_id,
          numericFlyerBookId,
          postId,
          numericImageId,
          formattedTimestamp,
        ],
      );

      const productId = productResult.insertId;

      if (!Array.isArray(keywords)) throw new Error('Keywords must be an array');

      for (const keyword of keywords) {
        const existingKeyword = await dbQuery(`SELECT keywordId FROM keywords WHERE keyword = ?`, [keyword]);
        let keywordId;
        if (existingKeyword.length > 0) {
          keywordId = existingKeyword[0].keywordId;
        } else {
          const newKeywordResult = await dbQuery(`INSERT INTO keywords (keyword) VALUES (?)`, [keyword]);
          keywordId = newKeywordResult.insertId;
        }
        await dbQuery(`INSERT INTO productkeywords (productId, keywordId) VALUES (?, ?)`, [productId, keywordId]);
      }
    }
    await dbQuery('COMMIT');
    allMessages.push('All products and keywords inserted successfully!');
  } catch (err) {
    await dbQuery('ROLLBACK');
    allMessages.push(`Error during product insertion: ${err.message}`);
    throw err;
  }
}

function normalizeProductForInsert(product) {
  if (!product || typeof product !== 'object') {
    return { normalized: null, reason: 'invalid-product-object', original: product };
  }

  const productDescription = String(product.product_description || '').trim();
  if (productDescription.length < 3) {
    return { normalized: null, reason: 'missing-or-short-description', original: product };
  }

  const newPriceNumber = parsePriceNumber(product.new_price);
  if (!Number.isFinite(newPriceNumber) || newPriceNumber <= 0 || newPriceNumber > 10000) {
    return { normalized: null, reason: 'invalid-new-price', original: product };
  }

  const oldPriceNumber = parsePriceNumber(product.old_price);
  const saleEndDate = String(product.sale_end_date || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(saleEndDate)) {
    return { normalized: null, reason: 'invalid-sale-end-date', original: product };
  }

  return {
    normalized: {
      ...product,
      product_description: productDescription,
      old_price: Number.isFinite(oldPriceNumber) && oldPriceNumber > 0 ? oldPriceNumber : 0,
      new_price: newPriceNumber,
      sale_end_date: saleEndDate,
    },
    reason: null,
    original: product,
  };
}

function parsePriceNumber(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : NaN;
  if (value === null || value === undefined) return NaN;

  const normalized = String(value)
    .trim()
    .replace(',', '.')
    .replace(/[^0-9.\-]/g, '');
  if (!normalized) return NaN;

  const parsed = Number.parseFloat(normalized);
  return Number.isFinite(parsed) ? parsed : NaN;
}

export async function logRejectedProducts(rejections) {
  if (!Array.isArray(rejections) || rejections.length === 0) return;

  const seenImageUrlsInBatch = new Set();
  const seenImageIdsInBatch = new Set();

  for (const entry of rejections) {
    const product = entry?.product && typeof entry.product === 'object' ? entry.product : {};
    const imageUrl = product.image_url ? String(product.image_url).trim() : '';
    const imageId = toNullableBigInt(product.imageId);

    // Skip duplicates within the same logging call first.
    if (imageUrl && seenImageUrlsInBatch.has(imageUrl)) continue;
    if (imageId !== null && seenImageIdsInBatch.has(imageId)) continue;

    // Skip duplicates already present in DB (image URL preferred, imageId fallback).
    if (imageUrl) {
      const existingByUrl = await queryPromise(
        `SELECT id FROM ingest_rejected_products WHERE image_url = ? LIMIT 1`,
        [imageUrl],
      );
      if ((existingByUrl?.length || 0) > 0) continue;
    } else if (imageId !== null) {
      const existingByImageId = await queryPromise(
        `SELECT id FROM ingest_rejected_products WHERE image_id = ? LIMIT 1`,
        [imageId],
      );
      if ((existingByImageId?.length || 0) > 0) continue;
    }

    if (imageUrl) seenImageUrlsInBatch.add(imageUrl);
    if (imageId !== null) seenImageIdsInBatch.add(imageId);

    await queryPromise(
      `INSERT INTO ingest_rejected_products
        (source, reason, store_id, user_id, post_id, image_id, flyer_book_id, image_url,
         product_description, old_price_raw, new_price_raw, sale_end_date_raw, raw_payload)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        String(entry?.source || 'unknown').slice(0, 120),
        String(entry?.reason || 'unknown').slice(0, 120),
        toNullableInt(product.storeId),
        toNullableInt(product.userId),
        toNullableBigInt(product.postId),
        imageId,
        product.flyer_book_id !== undefined && product.flyer_book_id !== null ? String(product.flyer_book_id).slice(0, 64) : null,
        imageUrl ? imageUrl.slice(0, 2048) : null,
        product.product_description ? String(product.product_description).slice(0, 500) : null,
        product.old_price !== undefined && product.old_price !== null ? String(product.old_price).slice(0, 64) : null,
        product.new_price !== undefined && product.new_price !== null ? String(product.new_price).slice(0, 64) : null,
        product.sale_end_date !== undefined && product.sale_end_date !== null ? String(product.sale_end_date).slice(0, 64) : null,
        JSON.stringify(product),
      ],
    );
  }
}

function toNullableInt(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function toNullableBigInt(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : null;
}
