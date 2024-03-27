const express = require("express");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    credentials: true,
    origin: [
      "http://localhost:3000",
      "http://localhost:8080",
      "http://localhost:5173",
    ],
  })
);
// Mock users - replace this with your own user authentication logic
const users = [{ id: 1, username: "user1", password: "password1" }];
// Configure options for JWT strategy

// Passport initialization
app.use(passport.initialize());
// Passport Local Strategy
passport.use(
  new LocalStrategy(function (username, password, done) {
    const user = users.find(
      (u) => u.username === username && u.password === password
    );
    if (!user) {
      return done(null, false, { message: "Incorrect username or password." });
    }
    return done(null, user);
  })
);

// Generate JWT token
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, "your_secret_key", {
    expiresIn: "2m",
  });
}
function generateRefreshToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, "your_secret_key", {
    expiresIn: "5m",
  });
}

function verifyToken(req, res, next) {
  const accessToken = req.cookies["jwt"];
  const refreshToken = req.cookies["refreshToken"];
  if (!accessToken) {
    return res.status(401).send("Access token not provided");
  }
  jwt.verify(accessToken, "your_secret_key", (err, user) => {
    if (!err) {
      req.user = user;
      res.status(200).json({
        status: "Success",
        content: req.user,
      });
      return next();
    }
    if (!refreshToken) {
      return res.status(401).send("Refresh token not provided");
    }
    jwt.verify(refreshToken, "your_secret_key", (err, user) => {
      if (err) {
        res.status(403).send("Invalid refresh token, Login");
        return clearCookies();
      }
      req.user = user;
      const newAccessToken = generateToken(req.user);
      res.cookie("jwt", newAccessToken, { httpOnly: true });
      return res.status(200).send("Token Refreshed!");
    });
  });
}
// Login route
app.post(
  "/login",
  passport.authenticate("local", { session: false }),
  (req, res) => {
    const accessToken = generateToken(req.user);
    const refreshToken = generateRefreshToken(req.user);
    // Set JWT as a cookie and set also refresh token
    res.cookie("jwt", accessToken, {
      httpOnly: true,
      sameSite: "None",
      secure: true,
    });
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      sameSite: "None",
      secure: true,
    });
    res.json({ accessToken });
  }
);
function clearCookies(req, res) {
  res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    sameSite: "None",
    secure: true,
  });
}
app.post("/logout", async (req, res) => {
  clearCookies(req, res);
  res.sendStatus(204);
});

// Protected route - example

app.get("/protected", verifyToken, async (req, res) => {
  console.log("Authenticated");
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
