import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import passport from 'passport';

// import passport from 'passport';



const GOOGLE_CLIENT_ID = "374131877123-1jdep4c6jinaa648k2f6b13ig26is9jn.apps.googleusercontent.com"
const GOOGLE_CLIENT_SECRET = "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";

passport.use(
    new GoogleStrategy(
  {
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback",
  },
  function (accessToken, refreshToken, profile, done) {
    done(null,profile );
  }
  )
);
passport.serializeUser((user,done)=>{
    done(null,user);
});
passport.deserializeUser((user,done)=>{
    done(null,user);
});