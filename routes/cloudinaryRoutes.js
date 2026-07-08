import express from 'express';
import multer from 'multer';
import {
  getMediaLibrary,
  renameImage,
  deleteImage,
  uploadImage,
  uploadMultipleImages,
} from '../controllers/cloudinaryController.js';

const upload = multer({ dest: 'uploads/' });

const router = express.Router();

router.get('/media-library-json', getMediaLibrary);
router.put('/rename-image', renameImage);
router.delete('/delete-image', deleteImage);
router.post('/upload', upload.array('images', 10), uploadImage);
router.post('/upload-multiple', upload.array('images', 10), uploadMultipleImages);

export default router;
