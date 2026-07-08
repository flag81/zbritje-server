import { formatDataToJson, extractSaleEndDateFromImage } from '../services/aiService.js';
import logger from '../services/logger.js';

const INGEST_DRY_RUN_DEFAULT = String(process.env.INGEST_DRY_RUN || '').toLowerCase() === 'true';

export const extractTextSingle = async (req, res) => {
  const images = req.body.images;
  if (!Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ message: 'No images array provided.' });
  }

  if (!images[0].storeId) {
    return res.status(400).json({ message: 'Missing storeId in request body.' });
  }

  const allMessages = [];
  const newImages = [...images];

  if (newImages.length === 0) {
    return res.status(400).json({ message: 'All imageIds already exist in database.' });
  }

  const { uploadMultipleFacebookPhotosToCloudinary } = await import('../uploadFacebookPhoto.js');
  const imageUrlsToUpload = images.map((img) => ({ imageUrl: img.imageUrl, imageId: img.imageId }));
  let uploadResults = [];
  let cloudinaryUrls = [];

  try {
    uploadResults = await uploadMultipleFacebookPhotosToCloudinary(imageUrlsToUpload);
    cloudinaryUrls = uploadResults.map((img) => img.uploadedUrl);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to upload images to Cloudinary', details: err.message });
  }

  const storeId = images[0].storeId;
  const postId = images[0].postId;
  const userId = images[0].userId || 1;
  const flyerBookId = images[0].flyerBookId;
  const postText = newImages.map((img) => img.postText || '');
  const imageId = images[0].imageId;
  const timestamp = images[0].timestamp;

  try {
    const products = await formatDataToJson(
      uploadResults,
      storeId,
      userId,
      flyerBookId,
      postText,
      postId,
      imageId,
      timestamp,
      { dryRun: INGEST_DRY_RUN_DEFAULT, runLabel: '/extract-text-single' },
    );

    res.json({ cloudinaryUrls, products, allMessages, debug: { input: images, uploaded: cloudinaryUrls } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process images', details: err.message });
  }
};

export const extractSaleEndDate = async (req, res) => {
  const { photos } = req.body;
  const imageUrls = photos;

  try {
    const results = [];
    for (const imageUrl of imageUrls) {
      let sale_end_date = null;
      try {
        sale_end_date = await extractSaleEndDateFromImage(imageUrl);
      } catch (err) {
        logger.error('Error extracting date for image:', imageUrl, err);
      }
      results.push({ image: imageUrl, sale_end_date: sale_end_date || null });
    }
    return res.json(results);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to extract sale end date from images.', error: err.message });
  }
};
