import express from 'express';
import {
  getProducts,
  getProductsDashboard,
  deleteProduct,
  updateProductPrices,
  editProductDescription,
  addKeyword,
  removeKeyword,
  addFavorite,
  removeFavorite
} from '../controllers/productController.js';
import { identifyUserMiddleware } from '../middleware/authMiddleware.js';

const router = express.Router();

// --- Public & App-Facing Routes ---
// This middleware will identify the user if a token is present, but won't block if not.
// The controller logic will handle cases where userId is null.
router.get('/', identifyUserMiddleware, getProducts);

// --- Admin/Dashboard Routes ---
router.get('/dashboard', getProductsDashboard);
router.delete('/:productId', deleteProduct);
router.put('/:productId/prices', updateProductPrices);
router.put('/:productId/description', editProductDescription);
router.post('/:productId/keywords', addKeyword);
router.delete('/:productId/keywords', removeKeyword);

// --- User-Specific Authenticated Routes ---
// These routes require a valid user to be identified.
router.post('/:productId/favorite', identifyUserMiddleware, addFavorite);
router.delete('/:productId/favorite', identifyUserMiddleware, removeFavorite);

export default router;