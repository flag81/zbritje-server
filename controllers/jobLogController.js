import { queryPromise } from '../dbUtils.js';
import logger from '../services/logger.js';

export const getJobLogs = async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 50;
  const offset = (page - 1) * limit;

  try {
    const q = `
      SELECT
        jl.id AS job_log_id,
        jl.job_name,
        jl.status,
        jl.message AS job_message,
        jl.created_at AS job_created_at,
        isl.id AS ingest_log_id,
        isl.store_id,
        isl.posts_fetched,
        isl.images_discovered,
        isl.images_uploaded,
        isl.images_with_products,
        isl.products_inserted,
        isl.errors AS ingest_errors,
        isl.created_at AS ingest_created_at,
        s.storeName,
        s.logo,
        s.active AS store_active
      FROM job_logs jl
      LEFT JOIN ingest_store_logs isl ON jl.id = isl.job_log_id
      LEFT JOIN stores s ON isl.store_id = s.storeId
      ORDER BY jl.created_at DESC, jl.id DESC, isl.id ASC
      LIMIT ? OFFSET ?
    `;
    const data = await queryPromise(q, [limit, offset]);

    const countResult = await queryPromise('SELECT COUNT(*) AS total FROM job_logs');
    const total = countResult[0]?.total || 0;

    res.json({ data, total, page, limit });
  } catch (err) {
    logger.error('getJobLogs error:', err);
    res.status(500).json({ error: 'Failed to retrieve job logs' });
  }
};
