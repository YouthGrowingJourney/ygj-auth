// server.js
const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const app = express();
const PORT = 3000;

app.use(session({
  secret: "ygj-secret-key", // kannst du später ändern
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // bei HTTPS später true
}));

app.use(express.json()); // Damit dein Server JSON versteht

// Speicherort für User-Daten (wir speichern sie erstmal lokal)
const usersFile = path.join(__dirname, "users.json");

// Hilfsfunktion: Benutzer laden
function loadUsers() {
  if (!fs.existsSync(usersFile)) return [];
  return JSON.parse(fs.readFileSync(usersFile));
}

// Hilfsfunktion: Benutzer speichern
function saveUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

// 🧾 Registrierung
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const users = JSON.parse(fs.readFileSync("users.json", "utf8"));

    // Prüfen, ob Nutzer bereits existiert
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ message: "Benutzername existiert bereits" });
    }

    // 🔒 Passwort sicher verschlüsseln
    const hashedPassword = await bcrypt.hash(password, 10);

    // Benutzer speichern
    users.push({ username, password: hashedPassword });
    fs.writeFileSync("users.json", JSON.stringify(users, null, 2));

    res.json({ message: "Registrierung erfolgreich!" });

  } catch (error) {
    console.error("Fehler bei der Registrierung:", error);
    res.status(500).json({ message: "Interner Serverfehler" });
  }
});

// 🔑 Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const users = JSON.parse(fs.readFileSync("users.json", "utf8"));

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ message: "Ungültige Anmeldedaten" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ message: "Ungültige Anmeldedaten" });
  }

  // ✅ Benutzer ist eingeloggt – Session speichern
  req.session.user = { username };
  res.json({ message: "Login erfolgreich!" });
});

app.get("/check-auth", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Erfolgreich ausgeloggt!" });
  });
});

app.listen(PORT, () => {
  console.log(`🔥 Server läuft auf http://localhost:${PORT}`);
});

// 🔒 Login-Schutz
async function checkAuth() {
  try {
    const response = await fetch("http://localhost:3000/check-auth", {
      credentials: "include"
    });
    const data = await response.json();

    if (!data.loggedIn) {
      // Wenn nicht eingeloggt → Weiterleitung zur Login-Seite
      window.location.href = "login.html";
    }
  } catch (error) {
    console.error("Fehler beim Auth-Check:", error);
    window.location.href = "login.html";
  }
}


