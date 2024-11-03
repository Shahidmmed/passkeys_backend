const express = require("express");
const cors = require("cors");
const app = express();
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("express-flash");

const initializaPassport = require("./passportConfig");
const passport = require("passport");

initializaPassport(passport);

const PORT = process.env.PORT || 4000;

app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60, // 1 hour in milliseconds
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.use(flash());

app.get("/", (req, res) => {
  res.send("Hello");
});

app.post("/auth/register", async (req, res) => {
  let { name, email, password } = req.body;

  let errors = [];

  if (!name || !email || !password) {
    errors.push({ message: "Please enter all fields" });
  } else if (password.length < 5) {
    errors.push({ message: "Password should be at least 5 characters" });
  }

  if (errors.length > 0) {
    res
      .status(400)
      .json({ status: "error", message: "Validation failed", errors });
  } else {
    try {
      let hashedPassword = await bcrypt.hash(password, 10);

      pool.query(
        `SELECT * FROM  users
      WHERE email = $1`,
        [email],
        (err, result) => {
          if (err) {
            throw err;
          }

          if (result.rows.length > 0) {
            res.status(400).json({
              status: "error",
              message: "Email already in use",
            });
          } else {
            pool.query(
              `INSERT INTO users (name,email,password)
            VALUES ($1, $2, $3)
            RETURNING name`,
              [name, email, hashedPassword],
              (err, result) => {
                if (err) {
                  throw err;
                }
                res.status(201).json({
                  status: "success",
                  message: "User created successfully",
                });
              }
            );
          }
        }
      );
    } catch (error) {
      res.status(500).json({
        status: "error",
        message: "Internal server error",
        error: error.message,
      });
    }
  }
});

app.post("/auth/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return res
        .status(500)
        .json({ status: "error", message: "An error occured" });
    }
    if (!user) {
      return res
        .status(401)
        .json({ status: "error", message: "Invalid credentials" });
    }
    req.logIn(user, (err) => {
      if (err) {
        return res
          .status(500)
          .json({ status: "error", message: "Login failed" });
      }

      const expires = req.session.cookie.expires
        ? req.session.cookie.expires.toISOString()
        : null;

      return res.status(200).json({
        status: "success",
        message: "Login successful",
        data: {
          token: user.token,
          session: { id: req.sessionID, expires: expires },
          user: { email: user.email, name: user.name },
        },
      });
    });
  })(req, res, next);
});

app.listen(PORT, () => {
  console.log(`server running on port ${PORT}`);
});
