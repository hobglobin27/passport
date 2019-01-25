const express = require("express");
const authRoutes = express.Router();
const zxcvbn = require("zxcvbn");
const passport = require("passport");
const ensureLogin = require("connect-ensure-login");

const User = require("../models/user");

const bcrypt = require("bcrypt");
const bcryptSalt = 10;

authRoutes.get("/signup",(req,res,next)=>{
  res.render("auth/signup");
});

authRoutes.post("/signup",(req,res,next)=>{
  const username=req.body.username;
  const password=req.body.password;

  if(username==="" || password===""){
    res.render("auth/signup",{
      message: "Indica un nombre de usuario y contraseña"
    })
    return;
  }

  if(zxcvbn(password).score < 1){
    res.render("auth/signup",{
      message: "El nivel de complejidad de tu password es bajo, favor de ingresar numeros, letras y caracteres especiales"
    })
    return;
  }

  User.findOne({username})
  .then(user=>{
    if(user !== null){
      res.render("auth/signup",{
        message: "El usuario ingresado ya existe"
      })
      return;
    }

    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashPass = bcrypt.hashSync(password,salt);

    const newUser = new User({
      username,
      password: hashPass
    })

    newUser.save((err)=>{
      if(err){
        res.render("auth/signup",{
          message: "Algo salio mal y no pude guardar tu registro. Intetalo de nuevo mas tarde"
        })
      }else{
        res.redirect("/");
      }
    })
  })
  .catch(error=>{
    next(error)
  })
})

authRoutes.get("/login",(req,res,next)=>{
  res.render("auth/login", {message:req.flash("error")})
})

authRoutes.post("/login", passport.authenticate("local",{
  successRedirect:"/private-page",
  failureRedirect:"/login",
  failureFlash:true,
  passReqToCallback:true
}))

authRoutes.get("/private-page", ensureLogin.ensureLoggedIn(),(req,res,next)=>{
  res.render("private",{user:req.user})
})

authRoutes.get("/logout",(req,res,next)=>{
  req.logout();
  res.redirect("login");
})

/////////////////////////////////Slack login////////////////////
authRoutes.get("/auth/slack", passport.authenticate("slack"));
authRoutes.get("/auth/slack/callback", passport.authenticate("slack", {
  successRedirect: "/private-page",
  failureRedirect: "/"
}));
////////////////////////////////////////////////////////////////

module.exports= authRoutes;
