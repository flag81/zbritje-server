//jshint esversion: 6
import mysql from 'mysql2';


const db = mysql.createPool({
  connectionLimit:4,
  host: "postgresql://admin:3gqLy9yx5alzqZni5ipJyw3EpelrI5Cr@dpg-crm28htumphs73eg4sr0-a.frankfurt-postgres.render.com/zbritje",
  user: "root",
  password: "prishtina81",
  database:"zbritje",
});

db.getConnection((err,connection)=> {
  if(err)
  throw err;
  //console.log('Database connected successfully');
  connection.release();
});

export default db;