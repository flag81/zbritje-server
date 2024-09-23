//jshint esversion: 6
import mysql from 'mysql2';


const db = mysql.createPool({
  connectionLimit:4,
  host: "mysql.railway.internal",
  user: "root",
  port: 3306,
  password: "sVclMskbFgSLmFwJcrIxhUELEHhSKMQo",
  database:"railway",
});

db.getConnection((err,connection)=> {
  if(err)
  throw err;
  console.log('Database connected successfully');
  connection.release();
});

export default db;