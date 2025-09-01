import express from 'express';
import { getUserProfile, updateUserProfile } from '../controllers/userController.js';
import { identifyUserMiddleware } from '../middleware/authMiddleware.js';

const router = express.Router();

// All user routes require an identified user.
router.use(identifyUserMiddleware);

router.get('/profile', getUserProfile);
router.put('/profile', updateUserProfile);

export default router;