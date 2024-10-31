const express = require("express");
const app = express();
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("express-flash");

const PORT = process.env.PORT || 4000;

app.use(express.urlencoded({ extended: false }));

app.use(session({ secret: "secret", resave: false, saveUninitialized: false }));
app.use(flash());

app.get("/", (req, res) => {
  res.send("Hello");
});

app.post("/users/register", async (req, res) => {
  let { name, email, password } = req.body;

  console.log({ name });

  let errors = [];

  if (!name || !email || !password) {
    errors.push({ message: "Please enter all fields" });
  }

  if (password.length < 5) {
    errors.push({ message: "Password should be at least 5 characters" });
  }

  if (errors.length > 0) {
    res.status(400).json({ errors });
  } else {
    let hashedPassword = await bcrypt.hash(password, 10);

    console.log(hashedPassword);

    pool.query(
      `SELECT * FROM  users
      WHERE email = $1`,
      [email],
      (err, result) => {
        if (err) {
          throw err;
        }

        console.log(result.rows);

        if (result.rows.length > 0) {
          errors.push({ message: "Email already in use" });
          res.status(400).json({ errors });
        } else {
          pool.query(
            `INSERT INTO users (name,email,password)
            VALUSE ($1, $2, $3)
            RETURNING id, password`,
            [name, email, hashedPassword],
            (err, result) => {
              if (err) {
                throw err;
              }
              console.log(result.rows);
            }
          );
        }
      }
    );
  }
});

app.listen(PORT, () => {
  console.log(`server running on port ${PORT}`);
});
