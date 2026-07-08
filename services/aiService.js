import { GoogleGenAI } from '@google/genai';
import axios from 'axios';
import JSON5 from 'json5';
import { insertProducts1, salvageProductsFromTruncatedJsonArray } from './productService.js';
import logger from './logger.js';

const aiStudio = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
const generativeModel = aiStudio.models;
const model = 'gemini-2.5-flash-lite';

export async function extractSaleEndDateFromImage(imageUrl) {
  const geminiPrompt = `You are an AI assistant that specializes in extracting sale end dates from images of retail flyers.
  The flyer is in Albanian language and the sale end date is usually written in a specific European format.
Your task is to analyze the image, identify the sale end date, and return it in the format YYYY-MM-DD.

Look for text patterns that indicate a date, such as "Sale ends on", "Valid until", or similar phrases.
Return the date in the format YYYY-MM-DD. If no date is found, return "No date found".`;

  const response = await generativeModel.generateContent({
    prompt: geminiPrompt,
    input: { image: { image_url: imageUrl } },
    response_format: {
      type: 'json',
      schema: {
        type: 'object',
        properties: {
          saleEndDate: { type: 'string', description: 'The extracted sale end date in YYYY-MM-DD format' },
        },
      },
    },
  });
  return response.candidates[0].content.saleEndDate || 'No date found';
}

export async function formatDataToJson(
  uploadResults,
  storeId,
  userId,
  flyerBookId,
  postText,
  postId,
  imageId,
  timestamp,
  options = {},
) {
  const dryRun = parseBooleanFlag(options.dryRun, false);
  const runLabel = options.runLabel || 'formatDataToJson';
  const diagnostics = options.diagnostics && typeof options.diagnostics === 'object' ? options.diagnostics : null;
  if (diagnostics) {
    if (!Array.isArray(diagnostics.imageResults)) diagnostics.imageResults = [];
    if (!Array.isArray(diagnostics.errors)) diagnostics.errors = [];
    diagnostics.quotaExhausted = diagnostics.quotaExhausted === true;
    diagnostics.abortReason = diagnostics.abortReason || null;
  }

  const recordImageResult = (result) => {
    if (diagnostics) diagnostics.imageResults.push(result);
  };
  const recordError = (error) => {
    if (diagnostics) diagnostics.errors.push(error);
  };

  const today = new Date();
  const formattedToday = today.toISOString().split('T')[0];
  const currentYear = today.getFullYear();

  let date;
  if (typeof timestamp === 'number' && !isNaN(timestamp)) {
    date = new Date(timestamp * 1000);
  } else if (typeof timestamp === 'string' && timestamp.trim() !== '') {
    date = new Date(timestamp);
  } else {
    date = new Date();
  }
  if (isNaN(date.getTime())) date = new Date();
  const formattedTimestamp = date.toISOString().slice(0, 19).replace('T', ' ');

  let allProducts = [];

  for (let i = 0; i < uploadResults.length; i++) {
    const { uploadedUrl } = uploadResults[i];
    const url = uploadedUrl;
    const imageIdForRun = uploadResults[i].imageId;

    const geminiPrompt = `You are an AI assistant that specializes in extracting structured product sale information from an image of an Albanian retail flyer extracted from Facebook Post.

Your task is to analyze the image, identify distinct product entries, and extract the product description, original price (if present), sale price, and discount percentage for each. A product entry typically consists of a product description and one or two prices. Original prices are usually higher and may be positioned near the sale price.

Analyze the visual layout and text content within the image to determine which elements belong to which product. 
Look for price patterns (numbers with currency symbols), percentage signs, and descriptive text.

Below is a categories array with category ids, descriptions and weights. Based on the description of the product, 
you will assign a category_id to each product that best matches the description of the product
to the categoryDescription in may belong in the array given.

[
  {"categoryId": 100, "categoryDescription": "Fruits (Fruta)", "categoryWeight": 80},
  {"categoryId": 101, "categoryDescription": "Vegetables (Perime)", "categoryWeight": 80},
  {"categoryId": 102, "categoryDescription": "Herbs (Erëza të Freskëta)", "categoryWeight": 80},
  {"categoryId": 103, "categoryDescription": "Red Meat (Mish i Kuq)", "categoryWeight": 62},
  {"categoryId": 104, "categoryDescription": "Poultry (Shpendë)", "categoryWeight": 62},
  {"categoryId": 105, "categoryDescription": "Processed Meats (Mishra të Përpunuar)", "categoryWeight": 59},
  {"categoryId": 106, "categoryDescription": "Fresh Fish (Peshk i Freskët)", "categoryWeight": 38},
  {"categoryId": 107, "categoryDescription": "Frozen Fish & Seafood (Peshk dhe Fruta Deti të Ngrira)", "categoryWeight": 70},
  {"categoryId": 108, "categoryDescription": "Canned Fish (Peshk i Konservuar)", "categoryWeight": 65},
  {"categoryId": 109, "categoryDescription": "Milk (Qumësht)", "categoryWeight": 82},
  {"categoryId": 110, "categoryDescription": "Yogurt (Kos / Jogurt)", "categoryWeight": 82},
  {"categoryId": 111, "categoryDescription": "Cheese (Djathë)", "categoryWeight": 82},
  {"categoryId": 112, "categoryDescription": "Cream (Ajkë / Krem Qumështi)", "categoryWeight": 82},
  {"categoryId": 113, "categoryDescription": "Butter (Gjalpë)", "categoryWeight": 82},
  {"categoryId": 114, "categoryDescription": "Margarine & Spreads (Margarinë dhe Produkte për Lyerje)", "categoryWeight": 64},
  {"categoryId": 115, "categoryDescription": "Eggs (Vezë)", "categoryWeight": 82},
  {"categoryId": 116, "categoryDescription": "Bread (Bukë)", "categoryWeight": 71},
  {"categoryId": 117, "categoryDescription": "Pastries & Croissants (Pasta dhe Kroasante)", "categoryWeight": 71},
  {"categoryId": 118, "categoryDescription": "Cakes & Sweet Baked Goods (Kekë dhe Ëmbëlsira Furre)", "categoryWeight": 71},
  {"categoryId": 119, "categoryDescription": "Flour (Miell)", "categoryWeight": 47},
  {"categoryId": 120, "categoryDescription": "Rice (Oriz)", "categoryWeight": 65},
  {"categoryId": 121, "categoryDescription": "Pasta & Noodles (Makarona dhe Fide)", "categoryWeight": 65},
  {"categoryId": 122, "categoryDescription": "Grains & Cereals (Drithëra)", "categoryWeight": 66},
  {"categoryId": 123, "categoryDescription": "Sugar & Sweeteners (Sheqer dhe Ëmbëltues)", "categoryWeight": 47},
  {"categoryId": 124, "categoryDescription": "Salt & Spices (Kripë dhe Erëza)", "categoryWeight": 47},
  {"categoryId": 125, "categoryDescription": "Cooking Oils (Vajra Gatimi)", "categoryWeight": 64},
  {"categoryId": 126, "categoryDescription": "Vinegar (Uthull)", "categoryWeight": 64},
  {"categoryId": 127, "categoryDescription": "Canned Goods (Konserva)", "categoryWeight": 65},
  {"categoryId": 128, "categoryDescription": "Sauces & Condiments (Salca dhe Kondimente)", "categoryWeight": 64},
  {"categoryId": 129, "categoryDescription": "Spreads (Produkte për Lyerje)", "categoryWeight": 64},
  {"categoryId": 130, "categoryDescription": "Chips & Crisps (Çipsa dhe Patatina)", "categoryWeight": 76},
  {"categoryId": 131, "categoryDescription": "Pretzels & Salty Snacks (Shkopinj të Kripur dhe Rosto të Tjera)", "categoryWeight": 76},
  {"categoryId": 132, "categoryDescription": "Nuts & Seeds (Fruta të Thata dhe Fara)", "categoryWeight": 76},
  {"categoryId": 133, "categoryDescription": "Chocolate (Çokollatë)", "categoryWeight": 43},
  {"categoryId": 134, "categoryDescription": "Biscuits & Cookies (Biskota dhe Keksa)", "categoryWeight": 76},
  {"categoryId": 135, "categoryDescription": "Candies & Gums (Karamele dhe Çamçakëz)", "categoryWeight": 43},
  {"categoryId": 136, "categoryDescription": "Frozen Vegetables & Fruits (Perime dhe Fruta të Ngrira)", "categoryWeight": 70},
  {"categoryId": 137, "categoryDescription": "Frozen Potato Products (Produkte Patatesh të Ngrira)", "categoryWeight": 70},
  {"categoryId": 138, "categoryDescription": "Frozen Ready Meals & Pizza (Gatime të Gata dhe Pica të Ngrira)", "categoryWeight": 70},
  {"categoryId": 139, "categoryDescription": "Frozen Meat & Fish (Mish dhe Peshk i Ngrirë)", "categoryWeight": 70},
  {"categoryId": 140, "categoryDescription": "Ice Cream (Akullore)", "categoryWeight": 70},
  {"categoryId": 141, "categoryDescription": "Baby Food (Ushqim për Foshnje)", "categoryWeight": 7},
  {"categoryId": 142, "categoryDescription": "Baby Formula (Qumësht Formule)", "categoryWeight": 7},
  {"categoryId": 143, "categoryDescription": "Water (Ujë)", "categoryWeight": 53},
  {"categoryId": 144, "categoryDescription": "Still Water (Ujë Natyral / pa Gaz)", "categoryWeight": 53},
  {"categoryId": 145, "categoryDescription": "Sparkling Water (Ujë Mineral / me Gaz)", "categoryWeight": 53},
  {"categoryId": 146, "categoryDescription": "Flavored Water (Ujë me Shije)", "categoryWeight": 53},
  {"categoryId": 147, "categoryDescription": "Fruit Juices (Lëngje Frutash)", "categoryWeight": 53},
  {"categoryId": 148, "categoryDescription": "Nectars (Nektare)", "categoryWeight": 53},
  {"categoryId": 149, "categoryDescription": "Smoothies (Smoothie)", "categoryWeight": 53},
  {"categoryId": 150, "categoryDescription": "Colas (Kola)", "categoryWeight": 53},
  {"categoryId": 151, "categoryDescription": "Other Carbonated Drinks (Pije të Tjera të Gazuara)", "categoryWeight": 53},
  {"categoryId": 152, "categoryDescription": "Coffee (Kafe)", "categoryWeight": 53},
  {"categoryId": 153, "categoryDescription": "Tea (Çaj)", "categoryWeight": 53},
  {"categoryId": 154, "categoryDescription": "Energy Drinks (Pije Energjetike)", "categoryWeight": 53},
  {"categoryId": 155, "categoryDescription": "Alcoholic Beverages (Pije Alkoolike)", "categoryWeight": 29},
  {"categoryId": 156, "categoryDescription": "Beer (Birrë)", "categoryWeight": 29},
  {"categoryId": 157, "categoryDescription": "Wine (Verë)", "categoryWeight": 29},
  {"categoryId": 158, "categoryDescription": "Spirits (Pije Spirtuore)", "categoryWeight": 29},
  {"categoryId": 159, "categoryDescription": "Laundry Detergents (Detergjentë Rrobash)", "categoryWeight": 59},
  {"categoryId": 160, "categoryDescription": "Fabric Softeners (Zbutës Rrobash)", "categoryWeight": 59},
  {"categoryId": 161, "categoryDescription": "Dishwashing Products (Produkte për Larjen e Enëve)", "categoryWeight": 59},
  {"categoryId": 162, "categoryDescription": "Surface Cleaners (Pastrues Sipërfaqesh)", "categoryWeight": 59},
  {"categoryId": 163, "categoryDescription": "Toilet Cleaners (Pastrues WC)", "categoryWeight": 59},
  {"categoryId": 164, "categoryDescription": "Garbage Bags (Thasë Mbeturinash)", "categoryWeight": 59},
  {"categoryId": 165, "categoryDescription": "Soaps & Shower Gels (Sapunë dhe Xhel Dushi)", "categoryWeight": 50},
  {"categoryId": 166, "categoryDescription": "Shampoos & Conditioners (Shampon dhe Balsam Flokësh)", "categoryWeight": 50},
  {"categoryId": 167, "categoryDescription": "Oral Care (Kujdesi Oral)", "categoryWeight": 50},
  {"categoryId": 168, "categoryDescription": "Deodorants & Antiperspirants (Deodorantë)", "categoryWeight": 50},
  {"categoryId": 169, "categoryDescription": "Skin Care (Kujdesi i Lëkurës)", "categoryWeight": 50},
  {"categoryId": 170, "categoryDescription": "Feminine Hygiene (Higjiena Femërore)", "categoryWeight": 50},
  {"categoryId": 171, "categoryDescription": "Paper Products (Produkte Letre)", "categoryWeight": 59},
  {"categoryId": 172, "categoryDescription": "Baby Diapers & Wipes (Pelena dhe Letra të Lagura për Foshnje)", "categoryWeight": 7},
  {"categoryId": 173, "categoryDescription": "Other", "categoryWeight": 1}
]

Extract the sale end dates either from the given post text: "${postText || ''}" or from the image itself. Return it in the format YYYY-MM-DD.
If there are multiple dates, return the latest one. If the year is missing, use the current year (${currentYear}). If the sale end date is missing, use today's date: ${formattedToday}.
Format the date in form "YYYY-MM-DD". If sale end date is less than ${formattedToday}, set valid_product to false.
Populate the sale_end_date field with the sale date found.

For each distinct product entry you identify in the image, create a JSON object in your output array with these exact keys and data types:

* \`product_description\` (string): The complete descriptive text associated with the product in the flyer. Include any size/volume information (e.g., 0,33L, 400ml, 3kg) if it's part of the product's description text in the flyer.
* \`old_price\` (string or null): The text of the original price (if a higher price is present). Remove currency symbols (€). If no distinct original price is found for a product, use \`null\`.
* \`new_price\` (string or null): The text of the current sale price (the lower price). Remove currency symbols (€). If no sale price is found, use \`null\`.
* \`discount_percentage\` (string or null): The numerical value of the discount percentage shown (e.g., "14"). Remove the percentage symbol (%). If no discount percentage is found, use \`null\`.
* \`sale_end_date\` (string): Use the extracted value from the flyer or post text. Format as "YYYY-MM-DD".
* \`storeId\` (number): Use the provided value: ${storeId}.
* \`userId\` (number): Use the provided value: ${userId}.
* \`postId\` (number): Use the provided value: ${postId}.
* \`imageId\` (number): Use the provided value: ${imageIdForRun}.
* \`timestamp\` (timestamp): Use the provided value: ${formattedTimestamp}.
* \`image_url\` (string): Use the current url of the image being processed store in ${url}.

* \`category_id\` (number or null): The numerical value of the categoryId extract from categories array.
*\`flyer_book_id\` (number or null): Use the provided value: "${flyerBookId}".
*\`valid_product\` (true or false): A boolean indicating if the product is valid based on the following criteria:
  - The product description must not be empty.
  - At least one of the prices (old_price or new_price) must be present.
  - The sale_end_date must be a valid date in the future (after today).

Also, generate a list of relevant keywords for each product description. These keywords should be in lowercase, in Albanian, 
and exclude common articles, conjunctions, prepositions, and size/volume information (like 'kg', 'l', 'pako', numbers, units). 
Only include words longer than 2 characters. Convert the Albanian letter 'ë' to 'e' for all keywords. 
If there is a keyword like "qumesht" or "qumësht" add a keyword "qumsht" as well to cover both spellings.
if there is a keyword like "veze" add a keyword "vo" as well to cover both spellings.
if there is a keyword like "shalqi*" add a keyword "bostan" as well to cover both spellings.
if there is a keyword like "ver*" add a keyword "vene" as well to cover both spellings.
if there is a keyword like "qepe" add a keyword "kep" as well to cover both spellings.
The \`keywords\` field should be an array of strings. Limit the keywords to the most relevant 5 per product.

To reduce response truncation risk:
- Return at most 25 product objects for one image.
- Return compact JSON only (no markdown, no prose, no comments, no code fences).
- If there are more than 25 offers, keep the clearest and most complete ones.

Provide ONLY the JSON array of extracted product objects in your response. Do not include any introductory or concluding text, explanations, or code block markers. Ensure the output is valid JSON.`;

    try {
      const imagePart = {
        inlineData: {
          mimeType: 'image/jpeg',
          data: Buffer.from(await axios.get(url, { responseType: 'arraybuffer' }).then((res) => res.data)).toString(
            'base64',
          ),
        },
      };

      const response = await generativeModel.generateContent({
        model: model,
        contents: [geminiPrompt, imagePart],
        config: {
          responseMimeType: 'application/json',
          temperature: 0.1,
          topP: 0.8,
          topK: 40,
          maxOutputTokens: 8192,
        },
      });

      let text = response.text;
      text = text
        .replace(/^```json\s*/, '')
        .replace(/\s*```$/, '')
        .replace(/`/g, '');

      try {
        const products = JSON5.parse(text);
        const validProducts = Array.isArray(products)
          ? products.filter((product) => product.valid_product !== false)
          : [];

        recordImageResult({
          storeId,
          imageId: imageIdForRun,
          validProductsCount: validProducts.length,
          source: 'parsed',
        });

        if (validProducts.length > 0) {
          if (dryRun) {
            logger.info(`[${runLabel}] Dry-run active, skipping DB insert for ${validProducts.length} products.`);
          } else {
            await insertProducts1(validProducts);
          }
        }
        allProducts = allProducts.concat(validProducts);
      } catch (parseError) {
        const salvagedProducts = salvageProductsFromTruncatedJsonArray(text);
        if (salvagedProducts.length > 0) {
          const validProducts = salvagedProducts.filter((product) => product.valid_product !== false);
          recordImageResult({
            storeId,
            imageId: imageIdForRun,
            validProductsCount: validProducts.length,
            source: 'salvaged',
          });
          if (validProducts.length > 0) {
            if (dryRun) {
              logger.info(
                `[${runLabel}] Dry-run active, skipping DB insert for salvaged ${validProducts.length} products.`,
              );
            } else {
              await insertProducts1(validProducts);
            }
            allProducts = allProducts.concat(validProducts);
          }
        } else {
          try {
            const retryPrompt = `${geminiPrompt}\n\nRETRY MODE: Your previous output was truncated/invalid. Return ONLY a compact valid JSON array, max 15 product objects.`;
            const retryResponse = await generativeModel.generateContent({
              model: model,
              contents: [retryPrompt, imagePart],
              config: {
                responseMimeType: 'application/json',
                temperature: 0.1,
                topP: 0.8,
                topK: 40,
                maxOutputTokens: 8192,
              },
            });

            let retryText = retryResponse.text;
            retryText = retryText
              .replace(/^```json\s*/, '')
              .replace(/\s*```$/, '')
              .replace(/`/g, '');

            const retryProducts = JSON5.parse(retryText);
            const validRetryProducts = Array.isArray(retryProducts)
              ? retryProducts.filter((product) => product.valid_product !== false)
              : [];

            recordImageResult({
              storeId,
              imageId: imageIdForRun,
              validProductsCount: validRetryProducts.length,
              source: 'retry-parsed',
            });

            if (validRetryProducts.length > 0) {
              if (dryRun) {
                logger.info(
                  `[${runLabel}] Dry-run active, skipping DB insert for retried ${validRetryProducts.length} products.`,
                );
              } else {
                await insertProducts1(validRetryProducts);
              }
              allProducts = allProducts.concat(validRetryProducts);
            }
          } catch (retryError) {
            recordError({
              storeId,
              imageId: imageIdForRun,
              type: 'json-parse',
              message: `${parseError.message}; retry API failed: ${retryError.message}`,
            });
            recordImageResult({ storeId, imageId: imageIdForRun, validProductsCount: 0, source: 'parse-failed' });
          }
        }
      }
    } catch (error) {
      const geminiError = classifyGeminiApiError(error);

      if (geminiError.isQuotaOrBilling) {
        const actionMessage = `${geminiError.message} Please top up billing credits in Google AI Studio and retry ingest.`;
        logger.error(
          `[formatDataToJson] Gemini quota/billing exhausted for store ${storeId}, image ${imageIdForRun}. Aborting remaining images for this store.`,
        );
        recordError({ storeId, imageId: imageIdForRun, type: 'gemini-quota', message: actionMessage });
        recordImageResult({ storeId, imageId: imageIdForRun, validProductsCount: 0, source: 'quota-exhausted' });
        if (diagnostics) {
          diagnostics.quotaExhausted = true;
          diagnostics.abortReason = actionMessage;
        }
        break;
      }

      logger.error(`[formatDataToJson] Gemini API Error for image #${i + 1}:`, error);
      recordError({ storeId, imageId: imageIdForRun, type: 'gemini-api', message: geminiError.message });
      recordImageResult({ storeId, imageId: imageIdForRun, validProductsCount: 0, source: 'api-failed' });
    }
  }
  return allProducts;
}

function classifyGeminiApiError(error) {
  const rawMessage = error?.message || 'Unknown Gemini API error.';
  let parsedPayload = null;

  if (typeof rawMessage === 'string' && rawMessage.trim().startsWith('{')) {
    try {
      parsedPayload = JSON.parse(rawMessage);
    } catch {
      parsedPayload = null;
    }
  }

  const payloadError = parsedPayload?.error;
  const code = Number(payloadError?.code || error?.status || error?.code || NaN);
  const status = String(payloadError?.status || '').toUpperCase();
  const payloadMessage = payloadError?.message || '';
  const normalizedMessage = `${rawMessage} ${payloadMessage}`.toLowerCase();

  const isQuotaOrBilling =
    code === 429 ||
    status === 'RESOURCE_EXHAUSTED' ||
    normalizedMessage.includes('resource_exhausted') ||
    normalizedMessage.includes('credits are depleted') ||
    normalizedMessage.includes('billing') ||
    normalizedMessage.includes('quota');

  const friendlyMessage = isQuotaOrBilling
    ? payloadMessage || 'Gemini API credits/quota are exhausted.'
    : rawMessage;

  return {
    isQuotaOrBilling,
    message: friendlyMessage,
  };
}

function parseBooleanFlag(value, fallback = false) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'y', 'on'].includes(normalized)) return true;
    if (['0', 'false', 'no', 'n', 'off'].includes(normalized)) return false;
  }
  return fallback;
}
