// middleware/identifyUserMiddleware.js
import jwt from 'jsonwebtoken';

const identifyUserMiddleware = (req, res, next) => {
  const token = req.cookies.jwt;
  req.identifiedUser = null; // Initialize

  if (token) {
    try {
      // Verify the token using the secret from environment variables
      const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
      // Attach decoded user information (userId, possibly email if included in token)
      // Ensure your JWT generation includes the necessary fields
      req.identifiedUser = decoded;
      console.log('✅ User Identified via JWT:', req.identifiedUser);
    } catch (err) {
      // If token is invalid (expired, wrong secret, etc.), clear the cookie
      console.warn('⚠️ Invalid JWT detected:', err.message);
      res.clearCookie("jwt");
    }
  } else {
    console.log('ℹ️ No JWT cookie found for identification.');
  }

  next(); // Proceed to the next middleware or route handler
};

export default identifyUserMiddleware;