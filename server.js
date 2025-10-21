// server.js
const express = require("express");
const session = require("express-session");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express(); // <== MUSS OBEN stehen 🔥

// === Middleware ===
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 🔥 Wichtig: CORS korrekt einstellen
app.use(cors({
  origin: "https://youthgrowingjourney.github.io",
  credentials: true
}));

app.use(bodyParser.json());

// 🔥 Session richtig konfigurieren
app.use(session({
  secret: "ygj_secret_key_123",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,           // wichtig für HTTPS
    httpOnly: true,         // schützt vor XSS
    sameSite: "none",       // erlaubt Cookies über verschiedene Domains
    maxAge: 1000 * 60 * 60  // 1 Stunde
  }
}));

// === Benutzerverwaltung im Speicher ===
let users = [];

// === ROUTEN ===

// Registrierung
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ message: "Missing fields" });

  if (users.find((u) => u.username === username))
    return res.status(400).json({ message: "Username already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, email, password: hashedPassword });
  res.json({ message: "User registered successfully" });
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: "Invalid credentials" });

  req.session.user = user.username;
  res.json({ message: "Login successful", user: user.username });
});

// Check Auth
app.get("/check-auth", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ message: "Logged out" });
  });
});

// === SERVER START ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🔥 Server läuft auf Port ${PORT}`);
});
