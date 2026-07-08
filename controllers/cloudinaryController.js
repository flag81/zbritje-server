import cloudinary from '../cloudinaryConfig.js';
import { listAllMediaFiles } from '../services/cloudinaryService.js';
import fs from 'fs';
import download from 'image-downloader';
import logger from '../services/logger.js';

export const getMediaLibrary = async (req, res) => {
  const mediaJson = await listAllMediaFiles();
  res.json(mediaJson);
};

export const renameImage = async (req, res) => {
  const { public_id, new_name } = req.body;
  if (!public_id || !new_name) return res.status(400).json({ error: 'Missing public_id or new_name' });
  try {
    const result = await cloudinary.uploader.rename(public_id, new_name);
    if (result.result === 'ok') {
      res.status(200).json({ message: 'Image renamed successfully' });
    } else {
      res.status(500).json({ error: 'Failed to rename image' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const deleteImage = async (req, res) => {
  const { public_id } = req.body;
  if (!public_id) return res.status(400).json({ error: 'Missing public_id' });
  try {
    const result = await cloudinary.uploader.destroy(public_id);
    if (result.result === 'ok') {
      res.status(200).json({ message: 'Image deleted successfully' });
    } else {
      res.status(500).json({ error: 'Failed to delete image' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const uploadImage = async (req, res) => {
  try {
    const uploadPromises = req.files.map(async (file) => {
      const imagePath = file.path;
      const result = await cloudinary.uploader.upload(imagePath, {
        folder: req.body.folderName || 'default-folder',
        use_filename: true,
        unique_filename: false,
        overwrite: true,
        transformation: [{ fetch_format: 'webp', quality: 'auto' }],
      });
      fs.unlinkSync(imagePath);
      return { success: true, url: result.secure_url, public_id: result.public_id, format: result.format };
    });
    const images = await Promise.all(uploadPromises);
    res.json({ success: true, images });
  } catch (error) {
    logger.error(error);
    res.status(500).json({ success: false, error: 'Failed to upload image' });
  }
};

export const uploadMultipleImages = async (req, res) => {
  const { folderName, storeId } = req.body;
  try {
    const uploadPromises = req.files.map(async (file) => {
      const imagePath = file.path;
      const result = await cloudinary.uploader.upload(imagePath, {
        folder: folderName || 'default-folder',
        use_filename: true,
        unique_filename: false,
      });
      const publicId = result.public_id;
      const imageName = publicId.split('/').pop();
      const transformationResult = await cloudinary.uploader.upload(publicId, {
        type: 'upload',
        overwrite: true,
        transformation: [
          {
            overlay: { font_family: 'Arial', font_size: 30, text: '#' + imageName + ' @' + storeId },
            gravity: 'north',
            y: -30,
            x: 10,
          },
        ],
      });
      fs.unlinkSync(imagePath);
      return { success: true, url: result.secure_url, public_id: result.public_id, format: result.format };
    });
    const results = await Promise.all(uploadPromises);
    res.json(results);
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to upload images' });
  }
};
