import express from "express";
import bodyParser from "body-parser";
import pg from "pg";

const app = express();
const port = 3000;

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
    console.log('user', user);
    if (user) { 
      res.send("This email already exists. Try logging in!");
    }else{
      // register user
      await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, password]);
      res.redirect("/login")
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
    const user = await getUser(email, password);
    console.log('user', user);
    
    if (!user) {
      res.send("Wrong email or password! Please try again!!!")
    } else {
      res.render("secrets.ejs")
    }
  } catch (error) {
    console.error('login:', error);
    
  }
});

async function getUser(email, password = null) {
  let user;
  if (password) {
    const result = await db.query("select * from users where email=$1 and password=$2", [email, password]);    
    user = result.rows[0] ?? null;
  } else {
    const result = await db.query("select * from users where email=$1", [email]);
    user = result.rows[0] ?? null;
  }
  return user;
}

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
