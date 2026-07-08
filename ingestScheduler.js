import { queryPromise } from './dbUtils.js';
import { fetchFacebookPosts } from './rapidApi.js';
import { uploadMultipleFacebookPhotosToCloudinary } from './uploadFacebookPhoto.js';
import logger from './services/logger.js';
import { enqueueGeminiBatchForStore, isGeminiBatchModeEnabled } from './services/geminiBatchIngestService.js';

function flattenFacebookPostsToItems(posts) {
  const items = [];
  posts.forEach((post) => {
    (post.images || []).forEach((imgObj) => {
      items.push({
        postId: post.postId,
        message: post.message,
        created_time: post.created_time,
        uri: imgObj.uri,
        image: imgObj.uri,
        imageData: post.imageData,
        imageId: imgObj.id,
        timestamp: post.timestamp,
      });
    });
  });
  return items;
}

/**
 * Runs the full ingest pipeline for all active stores (or a filtered subset):
 * 1. Fetch Facebook posts via RapidAPI
 * 2. Upload images to Cloudinary
 * 3. Extract product data with Gemini (formatDataToJson)
 * 4. Insert products into the DB
 *
 * @param {Function} formatDataToJson - The extraction + DB insert function from server.js
 * @param {number[]} [storeIds=[]] - Optional list of storeIds to limit processing. Empty = all active stores.
 */
export async function runDailyIngest(formatDataToJson, storeIds = [], options = {}) {
  const extractionMode = String(options?.extractionMode || process.env.INGEST_GEMINI_MODE || 'online').toLowerCase();
  const useBatchMode = isGeminiBatchModeEnabled(extractionMode);
  const filterLabel = storeIds.length > 0 ? `stores [${storeIds.join(', ')}]` : 'all active stores';
  logger.info(`[Ingest] Starting daily ingest job for ${filterLabel} (mode=${useBatchMode ? 'batch' : 'online'})...`);
  const storeSummaries = [];

  let stores;
  try {
    if (storeIds.length > 0) {
      stores = await queryPromise(
        `SELECT storeId, facebookPageId FROM stores WHERE active = true AND facebookPageId IS NOT NULL AND storeId IN (${storeIds.map(() => '?').join(',')})`,
        storeIds,
      );
    } else {
      stores = await queryPromise(
        'SELECT storeId, facebookPageId FROM stores WHERE active = true AND facebookPageId IS NOT NULL',
      );
    }
  } catch (err) {
    logger.error('[Ingest] Failed to fetch active stores:', err.message);
    return;
  }

  logger.info(`[Ingest] Found ${stores.length} stores to process (${filterLabel}).`);

  for (const store of stores) {
    const { storeId, facebookPageId } = store;
    const summary = {
      storeId,
      facebookPageId,
      postsFetched: 0,
      imagesDiscovered: 0,
      imagesUploaded: 0,
      imagesWithProducts: 0,
      productsInserted: 0,
      errors: [],
    };

    try {
      logger.info(`[Ingest] Processing store ${storeId} (page: ${facebookPageId})`);

      // 1. Fetch posts from Facebook via RapidAPI
      const posts = await fetchFacebookPosts(facebookPageId);
      const items = flattenFacebookPostsToItems(posts).filter((item) => Boolean(item.uri));
      summary.postsFetched = posts.length;
      summary.imagesDiscovered = items.length;

      if (items.length === 0) {
        logger.info(`[Ingest] No images found for store ${storeId}. Skipping.`);
        storeSummaries.push(summary);
        continue;
      }

      // 2. Upload images to Cloudinary
      const imageUrlsToUpload = items.map((item) => ({ imageUrl: item.uri, imageId: item.imageId }));
      const uploadResults = await uploadMultipleFacebookPhotosToCloudinary(imageUrlsToUpload);
      summary.imagesUploaded = uploadResults.length;

      if (uploadResults.length === 0) {
        logger.info(`[Ingest] No uploads succeeded for store ${storeId}. Skipping extraction.`);
        summary.errors.push({
          storeId,
          imageId: null,
          type: 'upload',
          message: 'No uploads succeeded for this store.',
        });
        storeSummaries.push(summary);
        continue;
      }

      if (useBatchMode) {
        try {
          const batchResult = await enqueueGeminiBatchForStore({
            storeId,
            uploadResults,
            sourceItems: items,
            userId: 1,
            flyerBookId: `${storeId}-${Date.now()}`,
            runLabel: 'daily-ingest-batch',
          });

          summary.errors.push(...(batchResult.errors || []));
          summary.productsInserted = 0;
          summary.imagesWithProducts = 0;
          logger.info(
            `[Ingest] Store ${storeId}: queued ${batchResult.itemCount} image requests in ${batchResult.batchCount} batch job(s).`,
          );
          storeSummaries.push(summary);
          continue;
        } catch (batchErr) {
          logger.error(
            `[Ingest] Batch enqueue failed for store ${storeId}, falling back to online extraction: ${batchErr.message}`,
          );
          summary.errors.push({
            storeId,
            imageId: null,
            type: 'batch-enqueue',
            message: `Batch enqueue failed, fallback to online mode: ${batchErr.message}`,
          });
        }
      }

      // 3. Run Gemini extraction + DB insert (dryRun: false = real insert)
      const diagnostics = { imageResults: [], errors: [] };
      const products = await formatDataToJson(
        uploadResults,
        storeId,
        1,
        `${storeId}-${Date.now()}`,
        items.map((item) => item.message || ''),
        items[0].postId || null,
        items[0].imageId || null,
        items[0].timestamp || Math.floor(Date.now() / 1000),
        { dryRun: false, runLabel: 'daily-ingest', diagnostics },
      );

      summary.productsInserted = products.length;
      summary.imagesWithProducts = diagnostics.imageResults.filter(
        (result) => Number(result.validProductsCount) > 0,
      ).length;
      summary.errors.push(...diagnostics.errors);

      logger.info(`[Ingest] Store ${storeId}: ${products.length} products inserted.`);
      storeSummaries.push(summary);
    } catch (err) {
      // One store failing does not stop the others
      logger.error(`[Ingest] Error processing store ${storeId}:`, err.message);
      summary.errors.push({
        storeId,
        imageId: null,
        type: 'store',
        message: err.message,
      });
      storeSummaries.push(summary);
    }
  }

  logger.info('[Ingest] Summary by store:');
  storeSummaries.forEach((summary) => {
    logger.info(
      `[Ingest][Store ${summary.storeId}] posts=${summary.postsFetched}, images=${summary.imagesDiscovered}, uploaded=${summary.imagesUploaded}, imagesWithProducts=${summary.imagesWithProducts}/${summary.imagesUploaded}, productsInserted=${summary.productsInserted}`,
    );
    if (summary.errors.length > 0) {
      summary.errors.forEach((error, idx) => {
        logger.info(
          `[Ingest][Store ${summary.storeId}][Error ${idx + 1}] imageId=${error.imageId ?? 'n/a'} type=${error.type} message=${error.message}`,
        );
      });
    }
  });

  logger.info('[Ingest] Daily ingest job complete.');
  return storeSummaries;
}
