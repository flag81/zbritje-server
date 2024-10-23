// for context use main.sql for database structure

import express from "express";
import cors from "cors";


import db from './connection.js';

import sessions from "express-session";
import cookieParser from "cookie-parser";

import path from 'path';

import jwt from 'jsonwebtoken';

import {fileURLToPath} from 'url';

import basicAuth from 'express-basic-auth';

const __filename = fileURLToPath(import.meta.url);

export const app = express();

import 'dotenv/config';


//const ts = require('./order')

//import { db, app } from "./db";
const __dirname = path.dirname(__filename);


app.use(cors());
app.use(express.json());

app.use(express.urlencoded({ extended: true }));

//serving public file
app.use(express.static(__dirname));

app.use(cookieParser());

var session ;

const auth = basicAuth({
  users: {
    admin: '123',
    user: '456',
  },
});


app.use(cookieParser('82e4e438a0705fabf61f9854e3b575af'));


app.get('/authenticate', auth, (req, res) => {
  const options = {
    httpOnly: true,
    signed: false,
    maxAge: 1000*60*60*24*7
  };

  console.log(req.auth.user);

  if (req.auth.user === 'admin') {
    res.cookie('name', 'admin', options).send({ screen: 'admin' });
  } else if (req.auth.user === 'user') {
    res.cookie('name', 'user', options).send({ screen: 'user' });
  }
});

app.get('/read-cookie', (req, res) => {
  console.log(req.signedCookies);
  if (req.signedCookies.name === 'admin') {
    res.send({ screen: 'admin' });
  } else if (req.signedCookies.name === 'user') {
    res.send({ screen: 'user' });
  } else {
    res.send({ screen: 'auth' });
  }
});

app.get('/clear-cookie', (req, res) => {
  res.clearCookie('name').end();
});

app.get('/get-data', (req, res) => {
  if (req.signedCookies.name === 'admin') {
    res.send('This is admin panel');
  } else if (req.signedCookies.name === 'user') {
    res.send('This is user data');
  } else {
    res.end();
  }
});



const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).send('A token is required for authentication');
  }
  try {
    const decoded = jwt.verify(token.split(' ')[1], process.env.TOKEN_SECRET);
    req.user = decoded;
  } catch (err) {
    return res.status(401).send('Invalid Token');
  }
  return next();
};



app.post('/auth', (req, res) => {
  // Mock user authentication
  const user = { username: req.body.username};

  console.log("username:", req.body.username);

  console.log("process.env.TOKEN_SECRET", process.env.TOKEN_SECRET);

  // Generate a token
  const token = jwt.sign(user, process.env.TOKEN_SECRET, { expiresIn: '24h' });
  res.json({ token });
});



app.get("/", (req, res) => {
  //res.json("hello from backend ...");
  res.sendFile(path.join(__dirname, 'index.html'));



});

app.get("/getUserEmail", (req, res) => {

  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
  const q = `SELECT email FROM users WHERE userId = "${req.query.userId}"`;
  

  console.log("getUserEmail:", q);

  const userId= req.query.userId;

  db.query(q, [userId], (err, data) => {

    if (err) {


      console.log("getUserEmail error:", err);
      return res.json(err);
    }

    return res.json(data);
  });
});


app.get("/getUserId", (req, res) => {

  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
  const q = `SELECT userId, expoPushToken FROM users WHERE userName = "${req.query.userName}"`;
  

  console.log("getUserId:",q);

  const userName= req.query.userName;

  db.query(q, [userName], (err, data) => {

    if (err) {
      console.log(err);
      return res.json(err);
    }

    return res.json(data);
  });
});

app.get("/", (req, res) => {

  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
  const q = `SELECT email FROM users WHERE userId = ${req.query.userId}`;
  

  const userId= req.query.userId;

  db.query(q, [userId], (err, data) => {

    if (err) {
      console.log(err);
      return res.json(err);
    }

    return res.json(data);
  });
});


//write a get endpoint getExpoPushNotificationToken that takes userId as a parameter and returns the expo push notification token for the user from users table

app.get("/getExpoPushNotificationToken", (req, res) => {
  
    //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
    const q = `SELECT expoPushToken FROM users WHERE userId = ${req.query.userId}`;
    
    const userId= req.query.userId;
  
    db.query(q, [userId], (err, data) => {
  
      if (err) {
        console.log(err);
        return res.json(err);
      }

      console.log("expoPushToken", data);
  
      return res.json(data);
    });
  });

  //write a get endpoint setExpoPushNotificationToken that takes userId and expoPushToken as parameters and updates the expo push notification token for the user in the users table

  app.put("/updateExpoPushNotificationToken", (req, res) => {

    //convert string to number
    const userId = parseInt(req.body.userId);


    console.log("userId",userId);

    

    //convert to string with escape characters
    const expoPushToken = req.body.expoPushToken;

    console.log("setExpoPushNotificationToken expoPushToken:::::",expoPushToken);


    const q = `UPDATE users SET expoPushToken="${expoPushToken}" WHERE userId = ${userId}`;


    console.log("q setExpoPushNotificationToken:",q);

    const values = [
      req.body.userId,
      req.body.expoPushToken
    ];

    //console.log(">>" + q);
    //console.log(">>" + req.body.expoPushToken);

    db.query(q, [values], (err, data) => {
      if (err) return res.send(err);

      //console.log("id",bookId)
      return res.json(data);
    });
  });


app.get("/getUserNotificationLevel", (req, res) => {

  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
  const q = `SELECT notificationLevel FROM users WHERE userId = ${req.query.userId}`;
  

  const userId= req.query.userId;

  db.query(q, [userId], (err, data) => {

    if (err) {
      console.log(err);
      return res.json(err);
    }

    return res.json(data);
  });
});


app.get("/prefetchProducts", (req, res) => {

  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
  const q = `SELECT products.productId as id, products.productName as title
  
  FROM products


  `;

  const userId= req.query.userId;

  db.query(q, [userId], (err, data) => {

    if (err) {
      console.log(err);
      return res.json(err);
    }

    return res.json(data);
  });
});

//write app.get like the one above that take paramerter a comma separated list of product ids and return the producct ids 
//and the product name of the products with the given ids

app.get("/getProductsByIds", (req, res) => {

  console.log("req.query.ids", req.query.ids)
  

    const q = `SELECT products.productId, products.productName, products.productPic, products.categoryId, products.storeId, products.productSize , products.subCategoryId,
    sales.saleId, sales.saleStartDate,sales.saleEndDate,sales.storeId,sales.storeLogo, sales.oldPrice, sales.discountPrice,
    sales.discountPercentage
  
  
  FROM products
  
  left join sales on products.productId = sales.productId

  where products.productId in (${req.query.ids})

  order by sales.saleEndDate desc

  `;

  console.log('q',q);
  
    const userId= req.query.userId;


    
  
    db.query(q, [userId], (err, data) => {
  
      if (err) {
        console.log(err);
        return res.json(err);
      }
  
      return res.json(data);
    });
  }
  );

app.get("/products",verifyToken, (req, res) => {


  let offset1 = parseInt(req.query.offset, 10);
  if (isNaN(offset1) || offset1 < 0) {
    offset1 = 0;
  } 
  else {
    // Multiply the valid offset by 10
    offset1 = (offset1 -1) * 10;
  }


  let userId = parseInt(req.query.userId, 10);
  if (isNaN(userId) || userId < 0) {
    userId = 0;
  } 

  let storeId = parseInt(req.query.storeId, 10);
  if (isNaN(storeId) || storeId < 0) {
    storeId = 0;
  } 

  let categoryId = parseInt(req.query.categoryId, 10);
  if (isNaN(categoryId) || categoryId < 0) {
    categoryId = 0;
  } 


  console.log("offset1:", offset1);

  console.log("storeId", storeId);

  console.log("userId", userId);

  console.log("categoryId", categoryId);


  let searchText = db.escape(req.query.searchText);

  let onSale = req.query.onSale;

  let isFavorite = req.query.isFavorite;


//get length of the string and console.log it
console.log("searchText", searchText);

  console.log("searchText length", searchText.length);




  //offset1 = parseInt(offset1);
  //console.log("valuessssss")
  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
// change the query so if storeId is greater than 0 then it will filter by storeId
// if storeId is 0 then it will return all products




  const q = 
  
  `
  SELECT 
  products.productId, 
  products.productName, 
  products.productPic, 
  products.categoryId, 
  products.productSize, 
  products.subCategoryId, 
  products.storeId, 
  products.imageUrl,
  products.productUrl,
  products.productRating,
  sales.saleId, 
  sales.saleStartDate,
  sales.saleEndDate,
  sales.storeLogo, 
  sales.oldPrice, 
  sales.discountPrice,
  sales.discountPercentage, 
  store.storeLogo as storeLogo,

  CASE 
    WHEN f.userId = ${userId} THEN true 
    ELSE false 
  END AS isFavorite,
  
  CASE 
    WHEN sf.id IS NOT NULL THEN true 
    ELSE false 
  END AS isStoreFavorite, -- Added this line to check if the store is a favorite
  
  CASE 
    WHEN CURRENT_DATE() BETWEEN sales.saleStartDate AND sales.saleEndDate THEN true 
    ELSE false 
  END AS onSale
  
FROM products
  
LEFT JOIN sales ON products.productId = sales.productId
LEFT JOIN store ON products.storeId = store.storeId
LEFT JOIN favorites f ON products.productId = f.productId and f.userId = ${userId}
LEFT JOIN storefavorites sf ON store.storeId = sf.storeId and sf.userId = ${userId} -- Assuming the join condition is correct


  WHERE 
  CASE 
    WHEN ${storeId} > 0 THEN products.storeId = ${storeId}
    ELSE true
  END

  and 

  CASE 
    WHEN ${categoryId} > 0 THEN products.categoryId = ${categoryId}
    ELSE true
  END

    and 

  CASE 

  WHEN ${onSale} = 1 THEN CURRENT_DATE() between sales.saleStartDate and sales.saleEndDate 
    ELSE true
  END

    and 

  CASE 
    WHEN ${searchText.length} > 2 THEN  INSTR(products.productName, ${searchText}) > 0

   
    ELSE true
  END

  and 
    (CASE 
        WHEN ${isFavorite} = 1 THEN f.id IS NOT NULL
        ELSE true
    END)



  order by isFavorite DESC,sales.saleEndDate DESC,
  isStoreFavorite DESC
  
  limit 10 OFFSET ${offset1} `;


  //LIMIT ${req.query.limit} OFFSET ${req.query.offset}
  //const userId= req.query.userId;

  //console.log("q",q);



  db.query(q, [storeId, offset1], (err, data) => {

    if (err) {
      console.log(err);
      return res.json(err);
    }

    return res.json(data);
  });
});


app.get("/getFavorites", (req, res) => {

//console.log("valuessssss")
const date = new Date();

let day = date.getDate();
let month = date.getMonth() + 1;
let year = date.getFullYear();

let today = year +"-"+ month + "-" + day;
console.log()
  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
  const q = `SELECT * FROM products join favorites on products.productId = favorites.productId where favorites.userId=? `;

  const userId=  parseInt(req.query.userId);

 // console.log("userid",userId);
  db.query(q, [userId], (err, data) => {

    if (err) {
      console.log(err);
      return res.json(err);
    }

    return res.json(data);
  });
});

app.get("/getProductOnSale", (req, res) => {

  //console.log("valuessssss")
  const date = new Date();

let day = date.getDate();
let month = date.getMonth() + 1;
let year = date.getFullYear();

let today = year +"-"+ month + "-" + day;
console.log()
//const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
const q = `SELECT products.productId, products.productName, products.productPic, products.categoryId, products.productSize , products.subCategoryId,
    sales.saleId, sales.productId,sales.saleStartDate,sales.saleEndDate,sales.storeId,sales.storeLogo, sales.oldPrice, sales.discountPrice,
    sales.discountPercentage

FROM products 
join sales on products.productId = sales.productId where 
CURRENT_DATE() between sales.saleStartDate and sales.saleEndDate`;

const userId=  parseInt(req.query.userId);

// console.log("userid",userId);
db.query(q, [userId], (err, data) => {

  if (err) {
    console.log(err);
    return res.json(err);
  }

  return res.json(data);
});
});


app.get("/getCategories", (req, res) => {

//const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
  const q = `SELECT * FROM categories `;

  const userId=  parseInt(req.query.userId);

  db.query(q, [userId], (err, data) => {

    if (err) {
      console.log(err);
      return res.json(err);
    }

    return res.json(data);
  });
});

// create a new endpoint isBrandFavorite that takes userId and brandId as parameters and returns true if the brand is favorite for the user and false otherwise
app.get("/isBrandFavorite", (req, res) => {

  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";

  const userId=  parseInt(req.query.userId);
  const brandId=  parseInt(req.query.brandId);
  
    const q = `SELECT count(userId) as cnt

    FROM brandfavorites
      
      WHERE brandfavorites.userId=${userId}
      AND
      brandfavorites.brandId=${brandId}

      `;

    //const userId=  parseInt(req.query.userId);

    db.query(q, [userId, brandId], (err, data) => {
        
        if (err) {
          console.log(err);
          return res.json(err);
        }
  
        return res.json(data);
      });
    }

  );
      


app.get("/isStoreFavorite", (req, res) => {

  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";

  const userId=  parseInt(req.query.userId);
  const storeId=  parseInt(req.query.storeId);


  
    const q = `SELECT count(userId) as cnt

    FROM storefavorites 
    
    WHERE storefavorites.userId=${userId} 
    AND
    storefavorites.storeId=${storeId}

     
    `;
  
    //const userId=  parseInt(req.query.userId);
  
    db.query(q, [userId, storeId], (err, data) => {
  
      if (err) {
        console.log(err);
        return res.json(err);
      }
  
      return res.json(data);
    });
  });

app.get("/getAllStores", (req, res) => {

  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";

  const userId=  parseInt(req.query.userId);



  
    const q = `SELECT store.storeId, store.storeName, store.storeLogoUrl, storefavorites.userId ,

        store.storeFacebookUrl,
        store.storeInstagramUrl,
        store.storePhone,
        store.storeAddress,
        store.storeWebsite,

       CASE 
        WHEN storefavorites.userId=${userId} THEN true 
        ELSE false 
        END AS isFavorite

    FROM store
    
    left join storefavorites on store.storeId = storefavorites.storeId

    and storefavorites.userId = ${userId}
    
    `;
  
    //const userId=  parseInt(req.query.userId);
  
    db.query(q, [userId], (err, data) => {
  
      if (err) {
        console.log(err);
        return res.json(err);
      }
  
      return res.json(data);
    });
  });


  // write the query so it returns the all the records from stores table and the isFavorite field is storeId is in the storefavorites table for the given userId






  


  

  


  app.get("/getStoreData", (req, res) => {

    //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
  
    const userId=  parseInt(req.query.userId);
    const storeId=  parseInt(req.query.storeId);
  
  // why does the query above return duplicae records from the stores table?
 
    
      const q = `SELECT store.storeId, store.storeName, store.storeLogoUrl, storefavorites.userId ,
  
                  CASE 
                    WHEN storefavorites.userId=${userId} THEN true 
                    ELSE false 
                    END AS isFavorite
            
                FROM store
                
                left join storefavorites on store.storeId = storefavorites.storeId
   
      
      `;
    
      //const userId=  parseInt(req.query.userId);
    
      db.query(q, [userId], (err, data) => {
    
        if (err) {
          console.log(err);
          return res.json(err);
        }
    
        return res.json(data);
      });
    });


  app.get("/getAllBrands", (req, res) => {

    //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";

    console.log("getAllBrands userid:", req.query.userId);
  
    const userId=  parseInt(req.query.userId);
  
  
    
      const q = `SELECT brands.brandId, brands.brandName, brands.brandLogoUrl, brandfavorites.userId ,
  
  
         CASE 
          WHEN brandfavorites.userId=${userId} THEN true 
          ELSE false 
          END AS isFavorite
  
      FROM brands
      
      left join brandfavorites on brands.brandId = brandfavorites.brandId

      and brandfavorites.userId = ${userId}
    
      `;
    
      //const userId=  parseInt(req.query.userId);
    
      db.query(q, [userId], (err, data) => {
    
        if (err) {
          console.log(err);
          return res.json(err);
        }
    
        return res.json(data);
      });
    });

  app.get("/getUserFavoriteStores", (req, res) => {

    //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
      const q = `SELECT userId, storeId FROM storeFavorites 
      
      

      WHERE userId = ?`;
    
      const userId=  parseInt(req.query.userId);
    
      db.query(q, [userId], (err, data) => {
    
        if (err) {
          console.log(err);
          return res.json(err);
        }
    
        return res.json(data);
      });
    });


    app.get("/getUserFavoriteBrands", (req, res) => {

      //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
        const q = `SELECT userId, brandId FROM brands WHERE userId = ?`;
      
        const userId=  parseInt(req.query.userId);
      
        db.query(q, [userId], (err, data) => {
      
          if (err) {
            console.log(err);
            return res.json(err);
          }
      
          return res.json(data);
        });
      });


app.get("/getSubCategories", (req, res) => {

  //const q = "SELECT tableid,  users.id  FROM orders join users on orders.userid = users.id WHERE orders.status = 0 ";
    const q = `SELECT * FROM subcategories `;
  
    const userId=  parseInt(req.query.userId);
  
    db.query(q, [userId], (err, data) => {
  
      if (err) {
        console.log(err);
        return res.json(err);
      }
  
      return res.json(data);
    });
  });



app.get("/checkIfUserNameExists", (req, res) => {

  const username = req.query.userName;

  //console.log("x",req.query.id);

  const q = "SELECT userId as found FROM users WHERE userName = ? ";
  db.query(q, [username], (err, data) => {


    if (err) {
      console.log(err);
      return res.json(err);
    }
    return res.json(data);
  });
});




app.get("/getOrder", (req, res) => {

  const tableId = req.query.id;

  //console.log("x",req.query.id);

  const q = "SELECT * FROM orders WHERE tableid = ? AND status = 0";
  db.query(q, [tableId], (err, data) => {


    if (err) {
      console.log(err);
      return res.json(err);
    }
    return res.json(data);
  });
});


app.put("/closeOrder", (req, res) => {
  const tableId = req.body.id;
  const q = "UPDATE orders SET `status`= 1 WHERE tableid = ?";

  db.query(q, [tableId], (err, data) => {
    if (err) return res.send(err);

    //console.log("id",bookId)
    return res.json(data);
  });
});


app.put("/updateOrder", (req, res) => {

  const tableId = req.body.id;
  const orderdata = req.body.orderdata;

  const myJSON = JSON.stringify(orderdata);


    const values = [

    req.body.orderdata,
    req.body.id,
   

  ];

   //orderdata = JSON.parse(orderdata)


  console.log(orderdata)
  const q = "UPDATE orders SET `orderdata`= ? WHERE tableid = ?";

  db.query(q, [myJSON, tableId], (err, data) => {
    if (err) return res.send(err);

    return res.json(data);
  });
});




app.get("/AllTables", (req, res) => {
  const q = "SELECT * FROM tables";
  db.query(q, (err, data) => {
    if (err) {
      console.log(err);
      return res.json(err);
    }
    return res.json(data);
  });
});


app.post("/add", (req, res) => {
  const q = "INSERT INTO tables(`nr`, `id`, `xcord`, `ycord`) VALUES (?)";

  const values = [
    req.body.nr,
    req.body.id,
    req.body.xcord,
    req.body.ycord,
  ];

  db.query(q, [values], (err, data) => {
    if (err) return res.send(err);
    return res.json(data);
  });
});

app.post("/addUser", (req, res) => {
 
    const my = {errors:''}
    console.clear();
    console.log("add user");
    const q = "INSERT INTO users(`userName`,`expoPushToken`) VALUES (?)";
  
    const values = [
      req.body.userName,
      req.body.expoPushToken
    ];
    console.log(">> addUser:" + values);
   
    db.query(q, [values], (err, data) => {
  
      if (err) return res.send(err);
      return res.json(data);
    });
  });



  
  
  app.put("/updateUserEmail", (req, res) => {

    //convert string to number
    const userId = parseInt(req.body.userId);

    //convert to string with escape characters
    const userEmail = db.escape(req.body.userEmail);

  
    const q = `UPDATE users SET email=${userEmail} WHERE userId = ${userId}`;

    const values = [
      req.body.userId,
      req.body.userEmail
    ];

    //console.log(">>" + q);
    //console.log(">>" + req.body.userEmail);
  
    db.query(q, [values], (err, data) => {
      if (err) return res.send(err);
  
      //console.log("id",bookId)
      return res.json(data);
    });
  });


  app.put("/updateUserNotificationLevel", (req, res) => {
  
    const q = `UPDATE users SET notificationLevel= ${req.body.notificationId} WHERE userId = ${req.body.userId}`;

    const values = [
      req.body.userId,
      req.body.notificationId
    ];
  
    db.query(q, [values], (err, data) => {
      if (err) return res.send(err);
  
      //console.log("id",bookId)
      return res.json(data);
    });
  });




app.post("/addFavorite", (req, res) => {
 
const my = {errors:''}

    //console.log("valuessssss111111")
  const q = "INSERT INTO favorites( `userId`, `productId`) VALUES (?)";

  const values = [
    req.body.userId,
    req.body.productId
  ];

  const userId = req.body.userId

  console.log(">>" + req.body.userId);
  console.log(">>" + req.body.productId);
  console.log(">>--" + req.method);



  db.query(q, [values], (err, data) => {

    if (err) return res.send(err);
    return res.json(data);
  });
});


// write a post endpoint addBrandToFavorites that takes userId and brandId as parameters and adds the brand to the user's favorite brands
app.post("/addBrandToFavorites", (req, res) => {
 
  const my = {errors:''}
  
      //console.log("valuessssss111111")
    const q = "INSERT INTO brandfavorites( `userId`, `brandId`) VALUES (?)";
  
    const values = [
      req.body.userId,
      req.body.brandId
    ];
  
    const userId = req.body.userId
  
    console.log(">>" + req.body.userId);
    console.log(">>" + req.body.brandId);
    console.log(">>--" + req.method);
  
  
  
    db.query(q, [values], (err, data) => {
  
      if (err) return res.send(err);
      return res.json(data);
    });
  });

app.post("/addStoreToFavorites", (req, res) => {
 
  const my = {errors:''}
  
     // console.log("valuessssss111111")
    const q = "INSERT INTO storefavorites( `userId`, `storeId`) VALUES (?)";
  
    const values = [
      req.body.userId,
      req.body.storeId
    ];
  
    const userId = req.body.userId
  
    console.log(">>" + req.body.userId);
    console.log(">>" + req.body.storeId);
    console.log(">>--" + req.method);
  
  
  
    db.query(q, [values], (err, data) => {
  
console.log("error",err)

      if (err) return res.send(err);
        
      
      return res.json(data);
    });
  });


app.post("/books", (req, res) => {
  const q = "INSERT INTO books(`title`, `desc`, `price`, `cover`) VALUES (?)";

  const values = [
    req.body.title,
    req.body.desc,
    req.body.price,
    req.body.cover,
  ];

  db.query(q, [values], (err, data) => {
    if (err) return res.send(err);
    return res.json(data);
  });
});

//write a post endpoint addBrand that takes brandId and userId as parameters and removes the brand from the user's favorite brands
app.delete("/removeBrandFromFavorites/:userId/:brandId", (req, res) => {

//console.log("usersssss");

const q = " DELETE FROM brandfavorites WHERE userId = ? and brandId = ? LIMIT 1";

const userId = req.params.userId;
const brandId = req.params.brandId;

console.log("user",req.params.userId)

db.query(q, [userId,brandId], (err, data) => {
  if (err)
  {
    console.log("error",err)
    return
  }

  return res.json(data);
});
});

app.delete("/removeStoreFromFavorites/:userId/:storeId", (req, res) => {


  //console.log("usersssss");

const q = " DELETE FROM storefavorites WHERE userId = ? and storeId = ? LIMIT 1";

const userId = req.params.userId;
const storeId = req.params.storeId;

console.log("user",req.params.userId)

db.query(q, [userId,storeId], (err, data) => {
  if (err) return res.send(err);
  return res.json(data);
});
});




app.delete("/removeFavorite/:userId/:productId", (req, res) => {


    //console.log("usersssss");

  const q = " DELETE FROM favorites WHERE userId = ? and productId = ? LIMIT 1";

  const userId = req.params.userId;
  const productId = req.params.productId;

console.log("user",req.params.userId)

  db.query(q, [userId,productId], (err, data) => {
    if (err) return res.send(err);
    return res.json(data);
  });
});


app.delete("/books/:id", (req, res) => {
  const bookId = req.params.id;
  const q = " DELETE FROM books WHERE id = ? ";

  db.query(q, [bookId], (err, data) => {
    if (err) return res.send(err);
    return res.json(data);
  });
});

app.put("/update/:id", (req, res) => {
  const bookId = req.params.id;
  const q = "UPDATE tables SET `xcord`= ?, `ycord`= ? WHERE id = ?";

  const values = [
    req.body.xcord,
    req.body.ycord,

  ];

  db.query(q, [...values,bookId], (err, data) => {
    if (err) return res.send(err);

    console.log("id",bookId)
    return res.json(data);
  });
});



app.listen(process.env.PORT, () => {
  console.log("Connected to backend.", process.env.PORT);
});