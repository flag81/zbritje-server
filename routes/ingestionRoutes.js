import express from 'express';
import { ingestStoreDryRun, triggerDailyIngest, pollGeminiBatchesNow } from '../controllers/ingestionController.js';

const router = express.Router();

router.post('/ingest-store-dry-run', ingestStoreDryRun);
router.post('/trigger-daily-ingest', triggerDailyIngest);
router.post('/poll-gemini-batches', pollGeminiBatchesNow);

export default router;
