// server.js (minimal korrigiert für Render + GitHub Pages)
const express = require("express");
const session = require("express-session");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

const app = express();

// Middlewares
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// WICHTIG für Render & Cookies hinter Proxy
app.set("trust proxy", 1);

// CORS: erlaubt Requests von deiner GitHub-Page + erlaubt Cookies
app.use(cors({
  origin: "https://youthgrowingjourney.github.io",
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"]
}));

// Session: proxy:true + cookie settings für Cross-Site cookies
app.use(session({
  secret: "ygj_secret_key_123",
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    secure: true,        // bei Render (HTTPS) -> true
    httpOnly: true,
    sameSite: "none",    // erlaubt Cookie cross-site
    maxAge: 1000 * 60 * 60 * 24 // 1 Tag
  }
}));

// === Simple in-memory users (wie gehabt) ===
let users = [];

// Registration (unchanged logic, hash pw)
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ message: "Missing fields" });
  }
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: "Username already exists" });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, email, password: hashedPassword });
  return res.json({ message: "User registered successfully" });
});

// Login: setzt req.session.user und gibt username zurück
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: "Invalid credentials" });

  // setze session (dies erzeugt das Set-Cookie header)
  req.session.user = user.username;

  // gib konsistente Antwort (script.js erwartet `username`)
  return res.json({ success: true, username: user.username });
});

// Check-auth: liest session und gibt username zurück
app.get("/check-auth", (req, res) => {
  if (req.session && req.session.user) {
    return res.json({ loggedIn: true, username: req.session.user });
  } else {
    return res.json({ loggedIn: false });
  }
});

// Logout: zerstört session und cleared cookie
app.post("/logout", (req, res) => {
  req.session.destroy(err => {
    // clear cookie, s.t. browser löscht es
    res.clearCookie("connect.sid", { path: "/", secure: true, sameSite: "none" });
    return res.json({ message: "Logged out" });
  });
});

// Server start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🔥 Server läuft auf Port ${PORT}`));
