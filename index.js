import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { getRounds } from "bcrypt"

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

const db = new pg.Client({
  user: "postgres",
  host : "localhost",
  port: 5432,
  password: "123456",
  database: "secrets"
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

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  
  try {
    // check user exists
    const user = await getUser(email);
    if (user) { 
      res.send("This email already exists. Try logging in!");
    }else{
      // register user
      bcrypt.hash(password, saltRounds, async (err, passHashed) => {
        if (err) {
          res.send("Error hashing password: ", err);
        } else {
          await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, passHashed]);
          res.redirect("/login")
        }
      });
    }
  } catch (error) {
    console.error('register:', error);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    // check user exists
    const user = await getUser(email);
    
    if (!user) {
      res.send("Wrong email ! Please try again!!!")
    } else {
      bcrypt.compare(password, user.password, (err, result) =>{
        if (!result) {
          res.send("Wrong password!");
        } else {
          res.render("secrets.ejs")
        }
      });
    }
  } catch (error) {
    console.error('login:', error);
    
  }
});

async function getUser(email) {
  const result = await db.query("select * from users where email=$1", [email]);
  let user = result.rows[0];
  console.log("user", user);
  
  return user ?? null;
}

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
