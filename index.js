import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SECRET_SESSION,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 // 1 day
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["email", "profile"]
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login"
  })
);

app.get("/logout", (req, res) => {
  req.logout(err => {
    err ? console.log("logout", err) : res.redirect("/login");
  });
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    // check user exists
    const user = await getUser(email);
    if (user) {
      res.send("This email already exists. Try logging in!");
    } else {
      // register user
      bcrypt.hash(password, saltRounds, async (err, passHashed) => {
        if (err) {
          res.send("Error hashing password: ", err);
        } else {
          await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [email, passHashed]
          );
          res.redirect("/login");
        }
      });
    }
  } catch (error) {
    console.error("register:", error);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login"
  })
);

async function getUser(email) {
  const result = await db.query("select * from users where email=$1", [email]);
  let user = result.rows[0];
  console.log("user", user);

  return user ? user : null;
}

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    const email = username;
    try {
      // check user exists
      const user = await getUser(email);

      if (!user) {
        return cb("User not found!");
      } else {
        bcrypt.compare(password, user.password, (err, result) => {
          if (err) {
            return cb(err);
          } else {
            if (!result) {
              return cb(err, false);
            } else {
              return cb(err, user);
            }
          }
        });
      }
    } catch (error) {
      return cb(error);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log("register", profile);
      try {
        const user = await getUser(profile.email);

        if (user) {
          // user already exist
          cb(null, user);
        } else {
          // new user
          const q = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) returning *",
            [profile.email, "google"]
          );

          const newUser = q.rows[0];
          cb(null, newUser);
        }
      } catch (error) {
        cb(error);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
