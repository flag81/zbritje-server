//jshint esversion: 6
import mysql from 'mysql2';




const db = mysql.createPool({
  connectionLimit:4,
  host: "autorack.proxy.rlwy.net",
  port: 51504,
  user: "root",
  password: "WQAbQaQZdMpXHhSuqQZRPoIIcufLPycF",
  database:"railway",
});

db.getConnection((err,connection)=> {
  if(err)
  throw err;
  //console.log('Database connected successfully');
  connection.release();
});

export default db;
