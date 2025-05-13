// In connection.js or a new utils/dbUtils.js
import db from './connection.js'; // Your existing db connection

/**
 * Executes a SQL query using the database connection pool and returns a Promise.
 * @param {string} sql The SQL query string.
 * @param {Array<any>} [params] Optional parameters for the query.
 * @returns {Promise<any>} A promise that resolves with the query results or rejects with an error.
 */
function queryPromise(sql, params) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, results) => {
      if (err) {
        console.error("Database Query Error:", err);
        return reject(err);
      }
      resolve(results);
    });
  });
}

export { queryPromise }; // Export alongside your db connection if modified in connection.js
// Or export default queryPromise; if in a separate file