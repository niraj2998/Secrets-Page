//jshint esversion:6

require('dotenv').config()
const express = require('express');
const path =  require('path');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose'); // passport-local is dependency of it 
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate'); 

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine','ejs')
app.use(express.static(path.join(__dirname,'public')));
app.use(express.urlencoded({extended: true}));
app.use(express.json());

app.use(session({
    secret: "our little secret",
    resave: false,
    saveUninitialized: false,

}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.DB_PATH, {useUnifiedTopology: true, useNewUrlParser: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User",userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" // google+ is senseting so to collect info from google user info instead og their google plus info
  },
  //here findOrCreate is a npm package we should install to make it work or you have to write a long function for it
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",(req,res) => {
    res.render('home');
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] }));

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

  app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.route("/register")
    .get((req,res) => {
    res.render('register');
    })
    .post((req,res) => {
        User.register({username: req.body.username}, req.body.password, (err, user) => {
            if(err){
                console.log(err);
                res.redirect("/register");
            }else{
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets")
                })
            }
        })
    });


app.get("/secrets",(req,res) => {
     User.find({"secret":{$ne: null}}, (err, foundUser) => {
       err ? console.log(err) : foundUser && res.render("secrets", {usersWithSecrets: foundUser});
     })
    });

app.get("/submit",(req,res) =>{
  if(req.isAuthenticated()){
    res.render("submit");
}else{
    res.redirect("/login");
}
});
app.post("/submit",(req,res) => {
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, (err, foundUser) => {
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save((err) => !err && res.redirect("/secrets") );
      }
    }
  })

})

app.route("/login")
    .get((req,res) => {
        res.render('login');
})
    .post((req,res) => {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });
        req.login(user, err => {
            err ? console.log(err) : passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets")
            })
        })
    });

app.get("/logout",(req, res) => {
    req.logout();
    res.redirect("/");
})

 


app.listen(PORT,() => {
    console.log(`server started at port ${PORT}`);
})