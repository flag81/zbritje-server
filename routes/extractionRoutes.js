import express from 'express';
import { extractTextSingle, extractSaleEndDate } from '../controllers/extractionController.js';

const router = express.Router();

router.post('/extract-text-single', extractTextSingle);
router.post('/extract-sale-end-date', extractSaleEndDate);

export default router;
