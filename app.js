require("dotenv").config()
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
var LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const parse = require('node-html-parser');
const axios = require("axios");
const bcrypt = require("bcrypt")
const flash = require("connect-flash");
const date = require('date-and-time') 
  
const app = express();

const API_AFFIRMATIONS = ("https://www.affirmations.dev/")

const now  =  new Date(); 


app.use(express.static("public"));
app.set("view engine", "ejs");
// Bodyparser
app.use(bodyParser.urlencoded({
  extended: true
}));
const port = 3000;

app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: "tellmeastory",
  resave: false,
  saveUninitialized: false,
}));

//Passport middleware tp manage sessions
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/dairyDB");


const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  username: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  data: {
    type: Date,
    default: Date.now
  },
  note: {
    type: String
  },
  goal: {
    note: {
      type: String
    }
  }

});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);


passport.use(new LocalStrategy({
  usernameField: "username"}, (username, password, done)=>{
    User.findOne({
      username: username
    }).then(user => {
      if (!user) {
        return done(null, false, {message: "That email is not registered" });
      }
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) throw err;
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, {message: "Password incorrect" });
        }
      });
    })
  })
  );

  // create the 'cookie' to store the user's data
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
     
    });
  });
});

// crumbled that 'cookie' to see the user's data
passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});


  // Connect flash
app.use(flash());

app.use((req, res, next) => {
    res.locals.success_msg = req.flash("success_msg");
    res.locals.error_msg = req.flash("error_msg");
    res.locals.error = req.flash("error");
    next()
});




  // authenticate method of google strategy
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/dailynotes",
    userProfileUrl: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb){
    console.log(profile);
    User.findOrCreate({
      googleId: profile.id
    }, function(err,user) {
      return cb(err,user);
    });
  }
  ));

 
// Routes

app.get("/", async (req, res)=>{
    res.render("home.ejs");
});

// Register Page
app.get("/register",async(req,res)=>{
    res.render("register.ejs")
});

// Register Handle
app.post("/register",async(req,res)=>{
   const { name, username, password, password2 } = req.body;
   let errors = [];

   //Check required fields
   if (!name || !username || !password || !password2) {
    errors.push({msg: "Please fill in all fields"})
   };

   // Check passwords match
   if(password !== password2){
    errors.push({msg: "Passwords do not match" });
   }

   //Check pass lenght
   if(password.length < 6) {
    errors.push({msg: "Passwords should be at least 6 characters"});
   }

   if(errors.length > 0 ){
    res.render('register', {
        errors, 
        name,
        username,
        password,
        password2
    });

   }else {
    // Validation passed
    User.findOne({username: username})
        .then(user => {
            if(user) {
                // User exists
                errors.push({ mesg: "Email is already registered" })
                res.render("register", {
                    errors,
                    name,
                    username,
                    password,
                    password2
                });
            } else{
                const newUser = new User({
                    name: name,
                    username,
                    password
                });

                // Hash Password
                bcrypt.genSalt(10, (err, salt) =>
                 bcrypt.hash(newUser.password, salt, (err, hash)=> {
                    if(err) throw err;
                    // Set password to hash
                    newUser.password = hash;
                    // Save User
                    newUser.save()
                    .then(user => {
                        req.flash("success_msg", "You are now registered and can log in.")
                        res.redirect("/login");
                    })
                    .catch(err => console.log(err));

                    
                }))
            }
        });
   }

});

// Google Authorization Routes

app.get("/auth/google",
  passport.authenticate("google", {
  scope: ["profile"]
}));

app.get("/auth/google/dailynotes", 
  passport.authenticate("google", {
    failureRedirect: "/login"
}),
  function(req, res) {
    // Succesul authentication, redirect daily notes
    res.render("userhome")
  });

  
  //Log in routes
app.get("/login",async(req,res)=>{
    res.render("login.ejs")
});

app.post("/login", (req, res, next) => {
  console.log("Login route hit");
  passport.authenticate("local", (err, user, info) => {
      console.log("Passport middleware called");
      if (err) {
          console.error(err);
          return next(err);
      }
      if (!user) {
          console.log("Authentication failed:", info.message);
          return res.redirect("/login");
      }
      req.logIn(user, (loginErr) => {
          if (loginErr) {
              console.error(loginErr);
              return next(loginErr);
          }
          console.log("Authentication successful");
          return res.redirect("/userhome");
      });
  })(req, res, next);
});

app.post("/logout", function(req, res, next){
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});


app.get("/userhome",async(req, res) => {
  try{
    const response = await axios.get(API_AFFIRMATIONS);
    console.log(response.data)
    console.log(User.note)
    res.render("userhome", {content: response.data});
  } catch (error) {
    console.log("Failed to make request", error.message)
  }

});

app.get("/addnote", (req,res)=> {
  if (req.isAuthenticated) {
    const value = date.format(now,'YYYY/MM/DD'); 
    console.log(value)
    res.render("addnote",{ today: value});
  } else {

    res.redirect("/login");
  }
})

app.listen(port, function () {
    console.log("server started on port ${port}.")
});