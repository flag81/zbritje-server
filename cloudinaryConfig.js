import { v2 as cloudinary } from 'cloudinary';

// Configure your Cloudinary account
cloudinary.config({
  cloud_name: 'dt7a4yl1x',     // Replace with your Cloudinary cloud name
  api_key: '443112686625846',  // Replace with your Cloudinary API key
  api_secret: 'e9Hv5bsd2ECD17IQVOZGKuPmOA4',  // Replace with your Cloudinary API secret
});

export default cloudinary;