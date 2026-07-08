import express from 'express';
import {
  getFacebookPhotos,
  getFacebookPostsHandler,
  getFacebookPhotosViaApify,
} from '../controllers/facebookController.js';

const router = express.Router();

router.get('/facebook-photos', getFacebookPhotos);
router.get('/facebook-posts', getFacebookPostsHandler);
router.post('/get-facebook-photos', getFacebookPhotosViaApify);

export default router;
