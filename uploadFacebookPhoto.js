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

export async function uploadMultipleFacebookPhotosToCloudinary(imageUrls) {
  if (!Array.isArray(imageUrls)) {
    throw new Error('imageUrls must be an array');
  }
  console.log('📸 Uploading multiple Facebook photos to Cloudinary:', imageUrls);

  const uploadedUrls = [];
  for (let i = 0; i < imageUrls.length; i++) {
    const url = imageUrls[i];
    try {
      console.log(`➡️ [${i + 1}/${imageUrls.length}] Uploading: ${url}`);
      const uploadedUrl = await uploadFacebookPhotoToCloudinary(url);
      uploadedUrls.push(uploadedUrl);
      console.log(`✅ Uploaded: ${uploadedUrl}`);
    } catch (err) {
      console.error(`❌ Failed to upload image at index ${i}: ${url}`, err.message);
      uploadedUrls.push(null); // Or skip, or handle as needed
    }
  }
  console.log('📦 All uploads complete:', uploadedUrls);
  return uploadedUrls;
}
