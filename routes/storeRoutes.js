import express from 'express';
import { getStores, getFacebookStores } from '../controllers/storeController.js';

const router = express.Router();

router.get('/', getStores);
router.get('/facebook', getFacebookStores);

export default router;
