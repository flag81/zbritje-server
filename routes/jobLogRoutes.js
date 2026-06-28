import express from 'express';
import { getJobLogs } from '../controllers/jobLogController.js';

const router = express.Router();

router.get('/', getJobLogs);

export default router;
