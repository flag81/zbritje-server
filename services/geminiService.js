import { GoogleGenAI } from '@google/genai';
import JSON5 from 'json5';
import path from 'path';
import { fileURLToPath } from 'url';
import logger from './logger.js';

// --- Configuration ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize Standard Google AI Studio SDK Client
const aiStudio = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
const model = 'gemini-2.5-flash-lite';

const MAX_RETRIES = 3;

/**
 * Creates a detailed, robust prompt for Gemini to ensure consistent JSON output.
 * This uses a "few-shot" learning approach by providing a clear example.
 * @param {object} params - The parameters for the prompt.
 * @returns {string} The fully constructed prompt.
 */
const buildPrompt = ({ storeId, flyerBookId, postId, imageId, timestamp }) => `
You are an expert data extraction bot for an Albanian sales flyer application.
Your task is to analyze a flyer image and extract all product information into a structured JSON format.

**Instructions & Schema Definition:**
- First, determine if the image is a sales flyer. If it is not a sales flyer (e.g., it's a logo, a single product photo, a meme, or a general announcement), return an empty products array: {"products": []}

- If it IS a sales flyer, extract every distinct product offer.
- Adhere strictly to the following JSON schema for each product.
- If a value is not present, use the specified default (e.g., 0 for price, null for date).
- All text, especially keywords, must be in Albanian.

**Field Definitions:**
- \`product_description\`: (string) The full product name, including brand, variant, and size/weight (e.g., "Kafe Lavazza 250 gr").
- \`old_price\`: (number) The original price before the discount. Default to 0 if not found.
- \`new_price\`: (number) The sale price. This is mandatory.
- \`discount_percentage\`: (number) The discount percentage shown on the flyer. If not shown, calculate it as round(((old_price - new_price) / old_price) * 100). Default to 0 if not applicable.
- \`sale_end_date\`: (string) The sale expiration date in "YYYY-MM-DD" format. Default to null if not found.
- \`storeId\`: (number) Use the provided store ID: ${storeId}.
- \`keywords\`: (string[]) An array of 3-5 relevant Albanian keywords for the product (e.g., ["kafe", "lavazza", "pije"]).
- \`flyer_book_id\`: (string) Use the provided ID: "${flyerBookId}".
- \`postId\`: (string) Use the provided ID: "${postId}".
- \`imageId\`: (string) Use the provided ID: "${imageId}".
- \`timestamp\`: (string) Use the provided timestamp: "${timestamp}".

**Example Output Format:**
Here is an example of the perfect output format. Follow this structure exactly.
{
  "products": [
    {
      "product_description": "Pampers Active Baby Pelena 80 copë",
      "old_price": 15.99,
      "new_price": 12.79,
      "discount_percentage": 20,
      "sale_end_date": "2025-09-15",
      "storeId": ${storeId},
      "keywords": ["pampers", "pelena", "fëmijë", "bebe"],
      "flyer_book_id": "${flyerBookId}",
      "postId": "${postId}",
      "imageId": "${imageId}",
      "timestamp": "${timestamp}"
    }
  ]
}

**Your Task:**
Now, analyze the following image and provide the JSON output in the specified format.
`;

/**
 * Extracts product data from a flyer image using the Gemini API with retry logic.
 * @param {string} imageUrl - The public URL of the image to analyze.
 * @param {object} metadata - An object containing storeId, flyerBookId, etc.
 * @returns {Promise<Array>} A promise that resolves to an array of product objects.
 */
export const extractProductsFromImage = async (imageUrl, metadata) => {
  const prompt = buildPrompt({ ...metadata, timestamp: new Date().toISOString().slice(0, 19).replace('T', ' ') });

  const imagePart = {
    inlineData: {
      mimeType: 'image/jpeg',
      data: Buffer.from(await fetch(imageUrl).then((res) => res.arrayBuffer())).toString('base64'),
    },
  };

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      logger.info(`[Gemini] Sending request for imageId: ${metadata.imageId} (Attempt ${attempt})`);
      const result = await aiStudio.models.generateContent({
        model: model,
        contents: [prompt, imagePart],
        config: {
          responseMimeType: 'application/json',
          temperature: 0.1,
        },
      });

      const responseText = result.text;
      const parsedJson = JSON5.parse(responseText);

      if (parsedJson && Array.isArray(parsedJson.products)) {
        logger.info(
          `[Gemini] Successfully extracted ${parsedJson.products.length} products for imageId: ${metadata.imageId}.`,
        );
        return parsedJson.products;
      }

      logger.warn(`[Gemini] Parsed JSON but 'products' array is missing or invalid for imageId: ${metadata.imageId}.`);
      return []; // Return empty array if structure is not expected
    } catch (error) {
      logger.error(`[Gemini] API Error on attempt ${attempt} for image ${metadata.imageId}:`, error.message);
      if (attempt === MAX_RETRIES) {
        throw new Error(`Failed to extract data from Gemini API after ${MAX_RETRIES} attempts.`);
      }
      // Wait before retrying (e.g., exponential backoff)
      await new Promise((res) => setTimeout(res, 1000 * attempt));
    }
  }
  return []; // Should not be reached, but as a fallback
};
