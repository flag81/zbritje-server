import axios from 'axios';
import fs from 'fs';
import tmp from 'tmp-promise';
import { v4 as uuidv4 } from 'uuid';
import cloudinary from './cloudinaryConfig.js'; // Adjust path if needed

export async function uploadFacebookPhotoToCloudinary(imageUrl) {


console.log('📸 Uploading Facebook photo to Cloudinary:', imageUrl);

  try {
    const tempFile = await tmp.file(); // Create temporary file

    // Download Facebook image to temp file
    const response = await axios({
      method: 'GET',
      url: imageUrl,
      responseType: 'stream',
    });

    const writer = fs.createWriteStream(tempFile.path);
    await new Promise((resolve, reject) => {
      response.data.pipe(writer);
      writer.on('finish', resolve);
      writer.on('error', reject);
    });

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(tempFile.path, {
      folder: 'uploads',
      public_id: uuidv4(),
      transformation: [
        { fetch_format: 'auto', quality: 'auto', dpr: 'auto' }
      ],
    });

    await tempFile.cleanup(); // Remove temp file
    return result.secure_url;
  } catch (err) {
    console.error('❌ Error uploading to Cloudinary:', err.message);
    throw err;
  }
}

export async function uploadMultipleFacebookPhotosToCloudinary(imageObjs) {
  if (!Array.isArray(imageObjs)) {
    throw new Error('imageUrls must be an array');
  }
  console.log('📸 Uploading multiple Facebook photos to Cloudinary:', imageObjs);


  // imageUrls is an array of objects with imageUrl and imageId
  if (imageObjs.length === 0) { 
    console.warn('⚠️ No images to upload.');
    return [];
  }


  const uploadedResults = [];
  for (let i = 0; i < imageObjs.length; i++) {
    const { imageUrl, imageId } = imageObjs[i];
    try {
      console.log(`➡️ [${i + 1}/${imageObjs.length}] Uploading: ${imageUrl} (imageId: ${imageId})`);
      const uploadedUrl = await uploadFacebookPhotoToCloudinary(imageUrl);
      uploadedResults.push({ imageId, uploadedUrl });
      console.log(`✅ Uploaded: ${uploadedUrl} (imageId: ${imageId})`);
    } catch (err) {
      console.error(`❌ Failed to upload image at index ${i}: ${imageUrl} (imageId: ${imageId})`, err.message);
      uploadedResults.push({ imageId, uploadedUrl: null }); // Or handle as needed
    }
  }
  console.log('📦 All uploads complete:', uploadedResults);
  return uploadedResults;
}
