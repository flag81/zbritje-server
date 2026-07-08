import { queryPromise } from '../dbUtils.js';
import { fetchFacebookPosts } from '../rapidApi.js';

export function flattenFacebookPostsToItems(posts) {
  const items = [];
  posts.forEach((post) => {
    (post.images || []).forEach((imgObj) => {
      items.push({
        postId: post.postId,
        message: post.message,
        created_time: post.created_time,
        uri: imgObj.uri,
        image: imgObj.uri,
        imageData: post.imageData,
        imageId: imgObj.id,
        timestamp: post.timestamp,
      });
    });
  });
  return items;
}

export async function getFacebookPosts(pageId) {
  const posts = await fetchFacebookPosts(pageId);
  const items = flattenFacebookPostsToItems(posts);
  return { posts, items };
}
