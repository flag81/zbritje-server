// facebookPhotos.mjs
import axios from 'axios';

export async function fetchFacebookPosts(pageId) {
  console.log(`📸 Extracting album images from: ${pageId} (single call)`);

  try {
    const response = await axios.get('https://facebook-scraper3.p.rapidapi.com/page/posts', {
      params: { page_id: pageId },
      headers: {
        'x-rapidapi-host': 'facebook-scraper3.p.rapidapi.com',
        'x-rapidapi-key': process.env.RAPID_API_KEY, // ✅ FIXED: Use environment variable for API key
      }
    });

    const posts = response.data.results || []; // ✅ FIXED: define 'posts'

    console.log(`📸 Found ${posts} posts for page: ${pageId}`); // Log the number of posts found

    const parsedPosts = posts.map(post => {
      const message = post.message || "";

      const timestamp = post.timestamp || "";

     console.log(`📸 Post timestamp: ${timestamp}`); // Log the timestamp for debugging

      const formattedTimeStamp = new Date(timestamp * 1000).toLocaleDateString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
      });

      const imageId = post.id || ""; // Use post.image.id if available, otherwise empty string

      // Initialize image list
      let images = [];
      let imageData = [];

      // Case 1: Album with multiple images
      if (Array.isArray(post.album_preview) && post.album_preview.length > 0) {
        //images = post.album_preview?.map(img => img.image_file_uri);
          images = post.album_preview.map(img => ({
            uri: img.image_file_uri,
            id: img.id,
          }));

        imageData = post.album_preview?.map(img => ({
          uri: img.image_file_uri,
          id: img.id,

        }));
      }

      // Case 2: Single image (if no album)
      else if (post.image?.uri) {
          images = [{
            uri: post.image.uri,
            id: post.image.id || "",
          }];
        imageData.push({
          uri: post.image.uri,
          id: post.image.id || "",
        });
      }

      // add post_id returned from json  to each post and return is with rest of of data
      const postId = post.post_id || post.id || ""; // Use post.id as fallback if post_id is not available
     


      return {
        message,
        images, // Will be [] if no media found
        imageData, // Will be [] if no media found
        postId, // Add postId to the returned object
        imageId,
        timestamp, // Add formatted date

      };
    });

    //console.log(parsedPosts);
    return parsedPosts;

  } catch (err) {
    console.error('❌ API error:', err?.response?.data || err.message);
    return [];
  }
}
