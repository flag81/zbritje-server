import db from '../connection.js';
import { queryPromise } from '../dbUtils.js';

export const getStores = (req, res) => {
  const q = `SELECT * from stores WHERE facebookPageId > 0 and active = true order by storeId asc`;
  db.query(q, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
};

export const getFacebookStores = (req, res) => {
  const q = `SELECT * from stores WHERE facebookPageId IS NOT NULL ORDER BY storeId ASC`;
  db.query(q, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
};
