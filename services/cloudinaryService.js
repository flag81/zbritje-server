import cloudinary from '../cloudinaryConfig.js';
import logger from './logger.js';

export async function listAllMediaFiles() {
  try {
    const result = await cloudinary.api.resources({
      type: 'upload',
      max_results: 100,
    });
    const mediaFiles = result.resources.map((resource) => ({
      public_id: resource.public_id,
      format: resource.format,
      secure_url: resource.secure_url,
      thumbnail_url: cloudinary.url(resource.public_id, {
        width: 100,
        height: 100,
        crop: 'thumb',
      }),
    }));
    return mediaFiles;
  } catch (error) {
    logger.error('Error fetching media files:', error);
    return { error: 'Error fetching media files' };
  }
}
