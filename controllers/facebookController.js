import { fetchFacebookPosts } from '../rapidApi.js';
import { getFacebookPosts } from '../services/facebookService.js';
import { ApifyClient } from 'apify-client';

const apify = new ApifyClient({ token: process.env.APIFY_TOKEN });

export const getFacebookPhotos = async (req, res) => {
  const pageId = req.query.facebookPageId;
  if (!pageId) return res.status(400).json({ error: 'Missing facebookPageId query parameter' });
  const data = await fetchFacebookPosts(pageId);
  const photoArray = Object.values(data.results || {});
  const allMessages = [];
  res.json({ items: photoArray, allMessages });
};

export const getFacebookPostsHandler = async (req, res) => {
  const pageId = req.query.facebookPageId;
  const debugMessages = [];
  if (!pageId) {
    return res.status(400).json({ error: 'Missing facebookPageId query parameter', debugMessages });
  }
  try {
    const { posts, items } = await getFacebookPosts(pageId);
    debugMessages.push(`Found ${posts.length} posts, ${items.length} images.`);
    res.json({ items, posts, debugMessages });
  } catch (err) {
    debugMessages.push(`API error: ${err?.message || err}`);
    res.status(500).json({ error: err.message, debugMessages });
  }
};

export const getFacebookPhotosViaApify = async (req, res) => {
  const { selectedStore, facebookUrl } = req.body;
  if (!facebookUrl) return res.status(400).json({ error: 'facebookUrl is required' });

  try {
    const facebookData = [{ url: facebookUrl, storeId: selectedStore }];
    const input = {
      startUrls: facebookData,
      resultsLimit: 10,
      proxy: { useApifyProxy: true, apifyProxyGroups: ['RESIDENTIAL'] },
    };
    const run = await apify.actor('apify/facebook-photos-scraper').call(input);
    const { items } = await apify.dataset(run.defaultDatasetId).listItems();
    res.json({ items });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch photos', details: err.message });
  }
};
