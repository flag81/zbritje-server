//jshint esversion: 6
import mysql from 'mysql2';

import dotenv from 'dotenv';

dotenv.config();



const db = mysql.createPool({
  connectionLimit:10,
  host: process.env.HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database:process.env.DB_NAME,
});

db.getConnection((err,connection)=> {
  if(err)
  throw err;
  console.log('Database connected successfully');
  connection.release();
});

export default db;