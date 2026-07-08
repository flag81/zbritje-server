import { v2 as cloudinary } from 'cloudinary';
import dotenv from 'dotenv';
import logger from '../services/logger.js';

dotenv.config();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

logger.info('✅ Cloudinary configured.');

export default cloudinary;
