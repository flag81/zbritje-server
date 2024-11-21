//jshint esversion: 6
import mysql from 'mysql2';


/*

const db = mysql.createPool({
  connectionLimit:4,
  host: "autorack.proxy.rlwy.net",
  port: 51504,
  user: "root",
  password: "WQAbQaQZdMpXHhSuqQZRPoIIcufLPycF",
  database:"railway",
});

*/

const db = mysql.createPool({
  connectionLimit:4,
  host: "128.140.43.244",
  port: 51504,
  user: "mysql",
  password: "u4BZPRXcHdt6MnFpgIq4K29gp6dTv1JM6B6ARiEa1apg0N6alUTfDgICG9o3wqjp",
  database:"default",
});


db.getConnection((err,connection)=> {

  console.log('Trying to connect');
  if(err)
  throw err;
  console.log('Database connected successfully');
  connection.release();
});

export default db;
