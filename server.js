const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const cors = require("cors");
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

// PostgreSQL setup
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "alumini_network",
  password: "root",
  port: 5432,
});


async function findUserByUsername(username) {
  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    return result.rows[0]; 
  } catch (error) {
    console.error("Error finding user by username:", error);
    throw error;
  }
}

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await findUserByUsername(username);
    if (user && await bcrypt.compare(password, user.password)) {
      const profileResult = await pool.query("SELECT * FROM alumni_profiles WHERE email = $1", [username]);
      const profileExists = profileResult.rows.length > 0;

      res.json({
        message: "Login successful",
        profileExists,
      });
    } else {
      res.status(401).json({ error: "Invalid username or password" });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Register
app.post("/register", async (req, res) => {
  const { username, password, securityQuestion, securityAnswer } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedAnswer = await bcrypt.hash(securityAnswer, 10);
    await pool.query(
      "INSERT INTO users (username, password, security_question, security_answer) VALUES ($1, $2, $3, $4)",
      [username, hashedPassword, securityQuestion, hashedAnswer]
    );
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    if (error.code === "23505") {
      res.status(400).json({ error: "Username already exists" });
    } else {
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

// Forgot Password
app.post("/forgot-password", async (req, res) => {
  const { username, securityAnswer } = req.body;
  try {
    const user = await findUserByUsername(username);
    if (!user) return res.status(400).json({ error: "Invalid username" });

    const isMatch = await bcrypt.compare(securityAnswer, user.security_answer);
    if (!isMatch) return res.status(400).json({ error: "Incorrect answer to security question" });

    const newPassword = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE users SET password = $1 WHERE username = $2", [hashedPassword, username]);

    res.json({ message: "Your new password is: " + newPassword });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Fetch Security Question
app.get("/security-question/:username", async (req, res) => {
  const { username } = req.params;
  try {
    const result = await pool.query("SELECT security_question FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0) return res.status(400).json({ error: "Invalid username" });

    res.json({ securityQuestion: result.rows[0].security_question });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Feedback Submission
app.post("/submit-feedback", async (req, res) => {
  const { subject, feedback } = req.body;

  if (!subject || !feedback) {
    return res.status(400).json({ error: "Subject and feedback are required" });
  }

  try {
    const query = "INSERT INTO feedback (subject, feedback, timestamp) VALUES ($1, $2, NOW())";
    await pool.query(query, [subject, feedback]);
    res.status(200).json({ message: "Feedback submitted successfully" });
  } catch (error) {
    console.error("Error saving feedback:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Multer setup for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Save images in 'uploads' folder
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Unique file name
  },
});
const upload = multer({ storage });

// Serve static files
app.use('/uploads', express.static('uploads'));

// Endpoint to save profile data
app.post('/save-profile', upload.single('profilePicture'), async (req, res) => {
  const { firstName, lastName, email, passingYear, branch, company, designation, linkedIn, achievement } = req.body;
  const profilePicture = req.file ? `/uploads/${req.file.filename}` : null;

  const achievements = achievement ? JSON.stringify([achievement]) : JSON.stringify([]);

  try {
    const result = await pool.query(
      `INSERT INTO alumni_profiles (first_name, last_name, email, passing_year, branch, company, designation, linkedin_url, profile_picture, achievements) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
      [firstName, lastName, email, passingYear, branch, company, designation, linkedIn, profilePicture, achievements]
    );
    res.json({ success: true, profile: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error saving profile' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
