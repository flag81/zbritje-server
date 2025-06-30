// facebookPhotos.mjs
import axios from 'axios';

export async function fetchFacebookPhotos(pageId) {


    console.log('📸 Fetching Facebook photos for page fron rapid api:', pageId);

  const allPhotos = [];
  let cursor = null;

  for (let page = 1; page <= 1; page++) {
    try {
      const response = await axios.get('https://facebook-scraper3.p.rapidapi.com/page/photos', {
        params: {
          page_id: pageId,
          ...(cursor && { cursor }), // include cursor only if it's defined
        },
        headers: {
          'x-rapidapi-host': 'facebook-scraper3.p.rapidapi.com',
          'x-rapidapi-key': '3e1574e969mshdb7f787e02bd267p14d308jsncb76c7ee6e6c',
        }
      });

      const photos = response.data.results || [];
      cursor = response.data.cursor || null;

      console.log(`📸 Page ${page}: Found ${photos.length} photos.`);

      allPhotos.push(...photos);

      if (!cursor) {
        console.log('❗ No more pages available.');
        break;
      }
    } catch (error) {
      console.error(`❌ Error on page ${page}:`, error?.response?.data || error.message);
      break;
    }
  }


   return { results:  allPhotos, cursor: cursor};


}
