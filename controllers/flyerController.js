import { extractProductsFromImage } from '../services/geminiService.js';
import { insertProducts } from './productController.js'; // We will add this function
import cloudinary from '../config/cloudinary.js';
import fetch from 'node-fetch';

// This controller will have functions to trigger processing.
// For now, let's assume the logic is triggered from an admin dashboard.
// The Apify logic would be in `apifyService.js` and called from here.

export const processFlyerImage = async (req, res) => {
    const { imageUrl, storeId, flyerBookId, postId, imageId } = req.body;

    if (!imageUrl || !storeId || !flyerBookId || !postId || !imageId) {
        return res.status(400).json({ error: 'Missing required parameters for flyer processing.' });
    }

    try {
        // 1. Upload to Cloudinary (if not already a cloudinary URL)
        // For simplicity, we assume imageUrl is a temporary URL that needs uploading.
        const uploadResponse = await cloudinary.uploader.upload(imageUrl, {
            folder: 'flyers',
        });
        const cloudinaryUrl = uploadResponse.secure_url;

        // 2. Extract products using Gemini Service
        const extractedProducts = await extractProductsFromImage(
            cloudinaryUrl,
            storeId,
            flyerBookId,
            postId,
            imageId
        );

        if (!extractedProducts || extractedProducts.length === 0) {
            return res.status(200).json({ message: 'No products found in the image.' });
        }

        // 3. Insert products into the database using a function from productController
        const insertResult = await insertProducts(extractedProducts);

        res.status(201).json({
            message: `Successfully processed and inserted ${insertResult.insertedCount} products.`,
            data: insertResult,
        });

    } catch (error) {
        console.error('[FlyerController] Error processing flyer:', error);
        res.status(500).json({ error: 'An internal error occurred during flyer processing.' });
    }
};