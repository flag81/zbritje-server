import { queryPromise } from '../dbUtils.js';
import { fetchFacebookPosts } from '../rapidApi.js';
import { flattenFacebookPostsToItems } from '../services/facebookService.js';
import { formatDataToJson } from '../services/aiService.js';
import { runDailyIngest } from '../ingestScheduler.js';
import { pollGeminiBatches } from '../services/geminiBatchIngestService.js';
import logger from '../services/logger.js';

const INGEST_STORE_IDS_DEFAULT = String(process.env.INGEST_STORE_IDS || '')
  .split(',')
  .map((id) => parseInt(id.trim(), 10))
  .filter(Number.isFinite);

function parseBooleanFlag(value, fallback = false) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const n = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'y', 'on'].includes(n)) return true;
    if (['0', 'false', 'no', 'n', 'off'].includes(n)) return false;
  }
  return fallback;
}

export const ingestStoreDryRun = async (req, res) => {
  const requestedStoreId = parseInt(req.body?.storeId ?? req.query?.storeId, 10);
  const requestedPageId = req.body?.facebookPageId ?? req.query?.facebookPageId;
  const maxImages = Math.max(1, parseInt(req.body?.maxImages ?? req.query?.maxImages ?? '8', 10) || 8);
  const dryRun = parseBooleanFlag(req.body?.dryRun ?? req.query?.dryRun, true);

  if (!Number.isFinite(requestedStoreId) && !requestedPageId) {
    return res.status(400).json({ error: 'storeId or facebookPageId is required.' });
  }

  if (
    Number.isFinite(requestedStoreId) &&
    INGEST_STORE_IDS_DEFAULT.length > 0 &&
    !INGEST_STORE_IDS_DEFAULT.includes(requestedStoreId)
  ) {
    return res
      .status(403)
      .json({ error: 'storeId is not allowed by INGEST_STORE_IDS scope.', allowedStoreIds: INGEST_STORE_IDS_DEFAULT });
  }

  const dbQuery = queryPromise;

  try {
    let storeId = requestedStoreId;
    let facebookPageId = requestedPageId;

    if (!facebookPageId && Number.isFinite(storeId)) {
      const storeRows = await dbQuery(
        'SELECT storeId, facebookPageId FROM stores WHERE storeId = ? AND active = true LIMIT 1',
        [storeId],
      );
      if (!storeRows.length || !storeRows[0].facebookPageId)
        return res.status(404).json({ error: 'No active store/facebookPageId found.' });
      facebookPageId = storeRows[0].facebookPageId;
    }

    if (!Number.isFinite(storeId) && facebookPageId) {
      const storeRows = await dbQuery('SELECT storeId FROM stores WHERE facebookPageId = ? AND active = true LIMIT 1', [
        facebookPageId,
      ]);
      if (storeRows.length) storeId = storeRows[0].storeId;
    }

    if (!Number.isFinite(storeId)) return res.status(400).json({ error: 'Unable to resolve a valid storeId.' });

    const posts = await fetchFacebookPosts(facebookPageId);
    const items = flattenFacebookPostsToItems(posts).filter((item) => Boolean(item.uri));
    const selectedItems = items.slice(0, maxImages);

    if (selectedItems.length === 0) {
      return res.status(200).json({
        message: 'No image items found.',
        dryRun,
        counts: { postsFetched: posts.length, imagesSelected: 0, productsExtracted: 0, productsInserted: 0 },
      });
    }

    const { uploadMultipleFacebookPhotosToCloudinary } = await import('../uploadFacebookPhoto.js');
    const imageUrlsToUpload = selectedItems.map((item) => ({ imageUrl: item.uri, imageId: item.imageId }));
    const uploadResults = await uploadMultipleFacebookPhotosToCloudinary(imageUrlsToUpload);

    const products = await formatDataToJson(
      uploadResults,
      storeId,
      1,
      `${storeId}-${Date.now()}`,
      selectedItems.map((item) => item.message || ''),
      selectedItems[0].postId || null,
      selectedItems[0].imageId || null,
      selectedItems[0].timestamp || Math.floor(Date.now() / 1000),
      { dryRun, runLabel: '/ingest-store-dry-run' },
    );

    return res.status(200).json({
      message: dryRun ? 'Dry-run completed.' : 'Ingestion completed.',
      dryRun,
      storeId,
      facebookPageId,
      counts: {
        postsFetched: posts.length,
        imagesSelected: selectedItems.length,
        imagesUploaded: uploadResults.length,
        productsExtracted: products.length,
        productsInserted: dryRun ? 0 : products.length,
      },
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to run ingestion.', details: error.message });
  }
};

export const triggerDailyIngest = async (req, res) => {
  const extractionMode = String(req.body?.extractionMode || process.env.INGEST_GEMINI_MODE || 'online').toLowerCase();
  const storeIds =
    Array.isArray(req.body?.storeIds) && req.body.storeIds.length > 0
      ? req.body.storeIds.map((id) => parseInt(id, 10)).filter(Number.isFinite)
      : [];
  const label = storeIds.length > 0 ? `stores [${storeIds.join(', ')}]` : 'all active stores';
  res.status(202).json({ message: `Daily ingest started for ${label} (mode=${extractionMode}). Check server logs.` });

  (async () => {
    try {
      const startResult = await queryPromise('INSERT INTO job_logs (job_name, status, message) VALUES (?, ?, ?)', [
        'manual-daily-ingest',
        'started',
        `Manual daily ingest for ${label}.`,
      ]);
      const jobLogId = startResult.insertId;
      const storeSummaries = await runDailyIngest(formatDataToJson, storeIds, { extractionMode });
      await queryPromise('INSERT INTO job_logs (job_name, status, message) VALUES (?, ?, ?)', [
        'manual-daily-ingest',
        'success',
        `Completed for ${label} (mode=${extractionMode}).`,
      ]);
      if (jobLogId && Array.isArray(storeSummaries)) {
        for (const s of storeSummaries) {
          await queryPromise(
            'INSERT INTO ingest_store_logs (job_log_id, store_id, posts_fetched, images_discovered, images_uploaded, images_with_products, products_inserted, errors) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [
              jobLogId,
              s.storeId,
              s.postsFetched,
              s.imagesDiscovered,
              s.imagesUploaded,
              s.imagesWithProducts,
              s.productsInserted,
              s.errors.length > 0 ? JSON.stringify(s.errors) : null,
            ],
          );
        }
      }
    } catch (err) {
      logger.error('[Manual] Daily ingest error:', err.message);
      try {
        await queryPromise('INSERT INTO job_logs (job_name, status, message) VALUES (?, ?, ?)', [
          'manual-daily-ingest',
          'failed',
          `Error for ${label}: ${err.message}`,
        ]);
      } catch (logErr) {
        logger.error('[Manual] Failed to write failed job_log row:', logErr.message);
      }
    }
  })();
};

export const pollGeminiBatchesNow = async (req, res) => {
  const limit = Math.max(1, parseInt(req.body?.limit ?? req.query?.limit ?? '20', 10) || 20);
  try {
    const summary = await pollGeminiBatches({ limit });
    return res.status(200).json({
      message: 'Gemini batch polling completed.',
      summary,
    });
  } catch (error) {
    logger.error('[Ingestion] pollGeminiBatchesNow failed:', error.message);
    return res.status(500).json({ error: 'Failed to poll Gemini batch jobs.', details: error.message });
  }
};
