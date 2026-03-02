//jshint esversion: 6
import mysql from 'mysql2';

import dotenv from 'dotenv';

dotenv.config();



//


const requiredEnv = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
const missingEnv = requiredEnv.filter((k) => !process.env[k]);
if (missingEnv.length) {
  console.error(`❌ Missing required DB env vars: ${missingEnv.join(', ')}`);
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
    console.error('❌ Database connection failed.');
    console.error(`   host=${process.env.DB_HOST} user=${process.env.DB_USER} db=${process.env.DB_NAME}`);
    if (err.code === 'ENOTFOUND') {
      console.error('   Cause: DB host DNS name could not be resolved from this server.');
      console.error('   Fix: set DB_HOST to a real resolvable hostname/IP for this environment,');
      console.error('        or (if using Docker) run the API in the same Docker network and use the DB service name.');
    }
    console.error('   Error:', err);
    process.exit(1);
  }

  console.log('✅ Database connected successfully');
  connection.release();
});

export default db;