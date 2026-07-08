//jshint esversion: 6
import mysql from 'mysql2';

import dotenv from 'dotenv';
import logger from './services/logger.js';

dotenv.config();



//


const requiredEnv = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
const missingEnv = requiredEnv.filter((k) => !process.env[k]);
if (missingEnv.length) {
  logger.error(`❌ Missing required DB env vars: ${missingEnv.join(', ')}`);
}

const db = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.getConnection((err, connection) => {
  if (err) {
    logger.error('❌ Database connection failed.');
    logger.error(`   host=${process.env.DB_HOST} user=${process.env.DB_USER} db=${process.env.DB_NAME}`);
    if (err.code === 'ENOTFOUND') {
      logger.error('   Cause: DB host DNS name could not be resolved from this server.');
      logger.error('   Fix: set DB_HOST to a real resolvable hostname/IP for this environment,');
      logger.error('        or (if using Docker) run the API in the same Docker network and use the DB service name.');
    }
    logger.error('   Error:', err);
    process.exit(1);
  }

  logger.info('✅ Database connected successfully');
  connection.release();
});

export default db;