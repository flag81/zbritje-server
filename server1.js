// Import required packages
const express = require('express');
var db= require('./connection.js');

// Initialize the Express application
const app = express();
const port = 3000; 

app.post('/cancel', (req,res) => {
  console.log('cancel clicked');
  var pnr= req.body.pnr;
  console.log(pnr);
  var sql3 = `DELETE FROM TICKET WHERE PNR='${pnr}'`;
  db.query(sql3, (err,data)=> {
  if(err)
     throw err;
    console.log("record deleted");
     });

   res.render("home_page");
});

// Define a simple route
app.get('/', (req, res) => {
  res.send('Hello, World!');
});

// Start the Express server
app.listen(port, () => {
  console.log(`Express server running at http://localhost:${port}`);
});