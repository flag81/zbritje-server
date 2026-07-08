import axios from 'axios';
import JSON5 from 'json5';
import { GoogleGenAI } from '@google/genai';
import { queryPromise } from '../dbUtils.js';
import { insertProducts1, salvageProductsFromTruncatedJsonArray } from './productService.js';
import logger from './logger.js';

const BATCH_MODEL = process.env.GEMINI_BATCH_MODEL || process.env.GEMINI_MODEL || 'gemini-2.5-flash-lite';
const BATCH_MAX_INLINE_REQUESTS = Math.max(1, parseInt(process.env.GEMINI_BATCH_MAX_INLINE_REQUESTS || '6', 10) || 6);

function normalizeMode(value) {
  return String(value || 'online').trim().toLowerCase();
}

export function isGeminiBatchModeEnabled(modeOverride) {
  const mode = normalizeMode(modeOverride || process.env.INGEST_GEMINI_MODE || 'online');
  return mode === 'batch';
}

function parseTimestampToUnixSeconds(timestamp) {
  if (typeof timestamp === 'number' && Number.isFinite(timestamp)) return Math.floor(timestamp);
  if (typeof timestamp === 'string' && timestamp.trim() !== '') {
    const numeric = Number(timestamp);
    if (Number.isFinite(numeric)) return Math.floor(numeric);
    const ms = Date.parse(timestamp);
    if (Number.isFinite(ms)) return Math.floor(ms / 1000);
  }
  return Math.floor(Date.now() / 1000);
}

function buildBatchPrompt({
  storeId,
  userId,
  flyerBookId,
  postText,
  postId,
  imageId,
  timestampUnix,
  imageUrl,
}) {
  const now = new Date();
  const today = now.toISOString().split('T')[0];
  const year = now.getFullYear();
  const ts = new Date(timestampUnix * 1000).toISOString().slice(0, 19).replace('T', ' ');

  return `You are an AI assistant extracting products from an Albanian retail flyer image.

Return ONLY a valid compact JSON array.
Each item must use this exact schema:
- product_description (string)
- old_price (string or null)
- new_price (string or null)
- discount_percentage (string or null)
- sale_end_date (YYYY-MM-DD string)
- storeId (number = ${storeId})
- userId (number = ${userId})
- postId (number = ${postId ?? 'null'})
- imageId (number = ${imageId ?? 'null'})
- timestamp (string = ${ts})
- image_url (string = ${imageUrl})
- category_id (number or null)
- flyer_book_id (number or string = ${flyerBookId})
- valid_product (boolean)
- keywords (array of max 5 lowercase Albanian strings without units/numbers)

Rules:
- Use post text as context: "${String(postText || '').replace(/"/g, '\\"')}"
- Find sale end date from image or post text. Use latest date if multiple.
- If year missing, use ${year}. If missing entirely, use ${today}.
- If sale_end_date is before ${today}, set valid_product to false.
- Keep only clear, complete offers.
- Maximum 25 products.
- No markdown, no prose, no code fences.`;
}

function getMimeType(headers) {
  const value = headers?.['content-type'] || headers?.['Content-Type'] || '';
  if (typeof value === 'string' && value.startsWith('image/')) return value.split(';')[0].trim();
  return 'image/jpeg';
}

function chunkArray(items, chunkSize) {
  const chunks = [];
  for (let i = 0; i < items.length; i += chunkSize) {
    chunks.push(items.slice(i, i + chunkSize));
  }
  return chunks;
}

async function createBatchJob(aiStudio, requests, displayName) {
  if (!aiStudio?.batches?.create) {
    throw new Error('Gemini SDK batches.create is not available in current @google/genai version.');
  }

  try {
    return await aiStudio.batches.create({
      model: BATCH_MODEL,
      src: requests,
      config: { displayName },
    });
  } catch {
    // Compatibility fallback for alternative key names used by some SDK versions.
    return await aiStudio.batches.create({
      model: BATCH_MODEL,
      src: requests,
      config: { display_name: displayName },
    });
  }
}

async function getBatchJob(aiStudio, batchName) {
  if (!aiStudio?.batches?.get) throw new Error('Gemini SDK batches.get is not available.');

  try {
    return await aiStudio.batches.get({ name: batchName });
  } catch {
    return await aiStudio.batches.get(batchName);
  }
}

function normalizeBatchState(stateValue) {
  const raw = typeof stateValue === 'string' ? stateValue : stateValue?.name || '';
  const state = String(raw || '').toUpperCase();
  if (!state) return 'JOB_STATE_PENDING';
  return state;
}

function extractResponseText(response) {
  if (!response) return '';
  if (typeof response.text === 'string' && response.text.trim() !== '') return response.text;

  const parts = response?.candidates?.[0]?.content?.parts;
  if (Array.isArray(parts)) {
    const text = parts
      .map((part) => (typeof part?.text === 'string' ? part.text : ''))
      .filter(Boolean)
      .join('\n');
    if (text) return text;
  }

  return '';
}

async function parseAndInsertProductsFromText(rawText) {
  if (!rawText || typeof rawText !== 'string') return 0;

  const cleaned = rawText
    .replace(/^```json\s*/i, '')
    .replace(/\s*```$/i, '')
    .replace(/`/g, '')
    .trim();

  let parsedProducts;
  try {
    const parsed = JSON5.parse(cleaned);
    parsedProducts = Array.isArray(parsed) ? parsed : [];
  } catch {
    parsedProducts = salvageProductsFromTruncatedJsonArray(cleaned);
  }

  const validProducts = parsedProducts.filter((product) => product && product.valid_product !== false);
  if (validProducts.length === 0) return 0;

  await insertProducts1(validProducts);
  return validProducts.length;
}

export async function enqueueGeminiBatchForStore({
  storeId,
  uploadResults,
  sourceItems,
  userId = 1,
  flyerBookId,
  runLabel = 'daily-ingest-batch',
}) {
  if (!Array.isArray(uploadResults) || uploadResults.length === 0) {
    return { batchCount: 0, itemCount: 0, rejectedCount: 0, errors: [] };
  }
  if (!process.env.GEMINI_API_KEY) {
    throw new Error('GEMINI_API_KEY is missing; cannot use batch mode.');
  }

  const aiStudio = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
  const sourceByImageId = new Map((sourceItems || []).map((item) => [String(item.imageId), item]));

  const prepared = [];
  const errors = [];

  for (const upload of uploadResults) {
    const imageId = upload?.imageId;
    const uploadedUrl = upload?.uploadedUrl;
    if (!uploadedUrl) continue;

    const source = sourceByImageId.get(String(imageId));
    if (!source) {
      errors.push({ storeId, imageId, type: 'batch-prepare', message: 'No source item found for uploaded image.' });
      continue;
    }

    try {
      const imageResp = await axios.get(uploadedUrl, { responseType: 'arraybuffer', timeout: 30000 });
      const mimeType = getMimeType(imageResp.headers);
      const base64Image = Buffer.from(imageResp.data).toString('base64');

      const request = {
        contents: [
          buildBatchPrompt({
            storeId,
            userId,
            flyerBookId,
            postText: source.message,
            postId: source.postId,
            imageId,
            timestampUnix: parseTimestampToUnixSeconds(source.timestamp),
            imageUrl: uploadedUrl,
          }),
          {
            inlineData: {
              mimeType,
              data: base64Image,
            },
          },
        ],
        config: {
          responseMimeType: 'application/json',
          temperature: 0.1,
          topP: 0.8,
          topK: 40,
          maxOutputTokens: 8192,
        },
      };

      prepared.push({
        imageId,
        uploadedUrl,
        postId: source.postId || null,
        timestampUnix: parseTimestampToUnixSeconds(source.timestamp),
        postText: source.message || '',
        flyerBookId,
        userId,
        request,
      });
    } catch (err) {
      errors.push({
        storeId,
        imageId,
        type: 'batch-prepare',
        message: `Failed to build batch request for image: ${err.message}`,
      });
    }
  }

  if (prepared.length === 0) {
    return { batchCount: 0, itemCount: 0, rejectedCount: uploadResults.length, errors };
  }

  const chunks = chunkArray(prepared, BATCH_MAX_INLINE_REQUESTS);
  let batchCount = 0;
  let itemCount = 0;

  for (let idx = 0; idx < chunks.length; idx++) {
    const chunk = chunks[idx];
    const requests = chunk.map((entry) => entry.request);
    const displayName = `${runLabel}-store-${storeId}-${Date.now()}-${idx + 1}`;

    const created = await createBatchJob(aiStudio, requests, displayName);
    const providerBatchName = created?.name;
    if (!providerBatchName) {
      throw new Error('Batch API did not return a batch name.');
    }

    const insertBatchResult = await queryPromise(
      `INSERT INTO ingest_gemini_batches (store_id, provider_batch_name, model_name, status, run_label, total_items, completed_items, failed_items, error_message)
       VALUES (?, ?, ?, ?, ?, ?, 0, 0, NULL)`,
      [storeId, providerBatchName, BATCH_MODEL, 'pending', runLabel, chunk.length],
    );

    const batchId = insertBatchResult.insertId;
    for (let itemIndex = 0; itemIndex < chunk.length; itemIndex++) {
      const item = chunk[itemIndex];
      await queryPromise(
        `INSERT INTO ingest_gemini_batch_items
          (batch_id, item_index, store_id, image_id, uploaded_url, post_id, timestamp_unix, post_text, flyer_book_id, user_id, status, products_inserted)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
        [
          batchId,
          itemIndex,
          storeId,
          item.imageId,
          item.uploadedUrl,
          item.postId,
          item.timestampUnix,
          item.postText,
          String(item.flyerBookId ?? ''),
          item.userId,
          'queued',
        ],
      );
    }

    batchCount += 1;
    itemCount += chunk.length;
    logger.info(`[GeminiBatch] Enqueued ${chunk.length} image requests in ${providerBatchName} for store ${storeId}.`);
  }

  return {
    batchCount,
    itemCount,
    rejectedCount: uploadResults.length - prepared.length,
    errors,
  };
}

async function markBatchFailed(batchId, message) {
  await queryPromise(
    `UPDATE ingest_gemini_batches
     SET status = 'failed', error_message = ?, updated_at = CURRENT_TIMESTAMP
     WHERE id = ?`,
    [message || 'Batch failed', batchId],
  );
  await queryPromise(
    `UPDATE ingest_gemini_batch_items
     SET status = 'failed', error_message = COALESCE(error_message, ?), updated_at = CURRENT_TIMESTAMP
     WHERE batch_id = ? AND status IN ('queued', 'running')`,
    [message || 'Batch failed', batchId],
  );
}

async function processSucceededBatch(batchRow, batchData) {
  const batchId = batchRow.id;
  const rows = await queryPromise(
    'SELECT id, item_index FROM ingest_gemini_batch_items WHERE batch_id = ? ORDER BY item_index ASC',
    [batchId],
  );

  const responses =
    batchData?.dest?.inlinedResponses ||
    batchData?.dest?.inlined_responses ||
    batchData?.dest?.inlinedresponses ||
    [];

  let completedItems = 0;
  let failedItems = 0;

  for (let i = 0; i < rows.length; i++) {
    const itemRow = rows[i];
    const inlineResp = responses[i];

    if (!inlineResp) {
      await queryPromise(
        `UPDATE ingest_gemini_batch_items
         SET status = 'failed', error_message = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        ['Missing inline response for batch item.', itemRow.id],
      );
      failedItems += 1;
      continue;
    }

    if (inlineResp.error) {
      const message =
        typeof inlineResp.error === 'string' ? inlineResp.error : JSON.stringify(inlineResp.error).slice(0, 5000);
      await queryPromise(
        `UPDATE ingest_gemini_batch_items
         SET status = 'failed', error_message = ?, raw_response = NULL, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [message, itemRow.id],
      );
      failedItems += 1;
      continue;
    }

    const responseText = extractResponseText(inlineResp.response);
    try {
      const inserted = await parseAndInsertProductsFromText(responseText);
      await queryPromise(
        `UPDATE ingest_gemini_batch_items
         SET status = 'completed', raw_response = ?, products_inserted = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [responseText.slice(0, 64000), inserted, itemRow.id],
      );
      completedItems += 1;
    } catch (err) {
      await queryPromise(
        `UPDATE ingest_gemini_batch_items
         SET status = 'failed', error_message = ?, raw_response = ?, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [err.message, responseText.slice(0, 64000), itemRow.id],
      );
      failedItems += 1;
    }
  }

  await queryPromise(
    `UPDATE ingest_gemini_batches
     SET status = 'succeeded', completed_items = ?, failed_items = ?, updated_at = CURRENT_TIMESTAMP
     WHERE id = ?`,
    [completedItems, failedItems, batchId],
  );

  return { completedItems, failedItems };
}

export async function pollGeminiBatches({ limit = 20 } = {}) {
  if (!process.env.GEMINI_API_KEY) {
    return { scannedBatches: 0, processedBatches: 0, completedItems: 0, failedItems: 0, skipped: 'missing-api-key' };
  }

  const aiStudio = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
  const batches = await queryPromise(
    `SELECT id, provider_batch_name, status
     FROM ingest_gemini_batches
     WHERE status IN ('pending', 'running')
     ORDER BY created_at ASC
     LIMIT ?`,
    [Math.max(1, Number(limit) || 20)],
  );

  let processedBatches = 0;
  let completedItems = 0;
  let failedItems = 0;

  for (const batchRow of batches) {
    try {
      const batchData = await getBatchJob(aiStudio, batchRow.provider_batch_name);
      const state = normalizeBatchState(batchData?.state);

      if (state === 'JOB_STATE_PENDING' || state === 'JOB_STATE_RUNNING') {
        await queryPromise(
          `UPDATE ingest_gemini_batches
           SET status = ?, updated_at = CURRENT_TIMESTAMP
           WHERE id = ?`,
          [state === 'JOB_STATE_RUNNING' ? 'running' : 'pending', batchRow.id],
        );
        continue;
      }

      processedBatches += 1;

      if (state === 'JOB_STATE_SUCCEEDED') {
        const summary = await processSucceededBatch(batchRow, batchData);
        completedItems += summary.completedItems;
        failedItems += summary.failedItems;
      } else {
        const errorMessage =
          batchData?.error?.message || (typeof batchData?.error === 'string' ? batchData.error : `Batch ended in state ${state}`);
        await markBatchFailed(batchRow.id, errorMessage);
      }
    } catch (err) {
      logger.error(`[GeminiBatch] Poll failed for ${batchRow.provider_batch_name}: ${err.message}`);
    }
  }

  return {
    scannedBatches: batches.length,
    processedBatches,
    completedItems,
    failedItems,
  };
}
