import express from 'express';
import { processFlyerImage } from '../controllers/flyerController.js';
// import { isAdminMiddleware } from '../middleware/authMiddleware.js'; // You would create this for security

const router = express.Router();

// This endpoint would likely be protected to ensure only admins can trigger it.
router.post('/process-image', processFlyerImage);

export default router;