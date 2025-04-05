require("dotenv").config();
const express = require('express');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const authenticateToken = require("./middleware/authemticateToken")
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 100000,
})

const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(200) NOT NULL UNIQUE,
        otp VARCHAR(6),
        otpExpires DATETIME,
        otp_verified BOOLEAN DEFAULT FALSE
    )`;

const predefineEmailAddress = [
    ["scbabai2704@gmail.com"],
    ["sugatachanda.cse2022@nsec.ac.in"]
]


db.query(createTableQuery, (err) => {
    if (err) {
        console.log("Error creating table:", err);
    }
    else {
        console.log("User table already exists or created successfully");

        db.query("INSERT IGNORE INTO users (email) VALUES ?", [predefineEmailAddress], (err, result) => {
            if (err) {
                console.log("Error inserting predefined email addresses:", err);
            }
            else {
                console.log("Predefined email addresses inserted successfully");
            }
        })
    }
})


const tranporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    service: "gmail",
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
})

const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

app.post('/send-otp', (req, res) => {
    const { email } = req.body;

    if (!email) return res.status(400).json({ message: "Email is required" });

    db.query("SELECT * FROM users WHERE email = ?", [email], (err, result) => {
        if (err) return res.status(500).json({ message: err.message });

        if (result.length === 0) {
            return res.status(404).json({ message: "Email not found" });
        }

        const otp = generateOTP()

        let template = fs.readFileSync(path.join(__dirname, 'otp_template.html'), 'utf-8');
        template = template.replace('{{OTP}}', otp, '{{email}}', email);

        const otpExpires = new Date(Date.now() + 5 * 60 * 1000)

        db.query("UPDATE users SET otp = ?, otp_expires = ?  WHERE email = ?", [otp, otpExpires, email], (err) => {
            if (err) return res.status(500).json({ message: err.message });
            const mailOptions = {
                from: `"Techno India Group" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: "OTP for Login",
                text: `Your OTP for login is ${otp}. It will expire in 5 minutes.`,
                html: template
            }

            tranporter.sendMail(mailOptions, (err) => {
                if (err) return res.status(500).json({ message: err.message });
                res.json({ message: "OTP sent successfully" })
            })
        })
    })
})

app.post("/verify-otp", (req, res) => {
    const { email, otp } = req.body;

    if (!otp) {
        return res.status(400).json({ message: "Email and OTP are required" });
    }

    const query = `SELECT otp, otp_expires FROM users WHERE email = ?`;
    db.query(query, [email], (err, results) => {
        if (err) {
            return res.status(500).json({ message: "Database error", error: err });
        }

        if (!results || results.length === 0) {
            return res.status(400).json({ message: "User not found" });
        }

        const { otp: storedOTP, otp_expires, otp_verified } = results[0];

        if (!storedOTP) {
            return res.status(400).json({ message: "No OTP found. Request a new OTP." });
        }

        if (otp_verified) {
            return res.status(400).json({ message: "OTP already verified. Please request a new OTP." });
        }

        if (otp !== storedOTP) {
            return res.status(400).json({ message: "Invalid OTP" });
        }

        if (otp_expires && new Date() > new Date(otp_expires)) {
            return res.status(400).json({ message: "OTP expired. Request a new OTP." });
        }

        // db.query(`UPDATE users SET otp_verified = TRUE WHERE email = ?`, [email], (err) => {
        //     if (err) {
        //         return res.status(500).json({ message: "Database error", error: err });
        //     }
        // });

        const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1m' });

        res.json({ success: true, message: "OTP verified successfully", token });
    });
});

app.delete("/delete-user", (req, res) => {
    const { email } = req.body; // Get email from request body

    if (!email) {
        return res.status(400).json({ message: "Email is required" });
    }

    const query = `DELETE FROM users WHERE email = ?`;

    db.query(query, [email], (err, result) => {
        if (err) {
            return res.status(500).json({ message: "Database error", error: err });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({ success: true, message: "User deleted successfully" });
    });
});

app.post('/logout', (req, res) => {
    const { email } = req.body;

    console.log("Auto Logout Triggered for:", email);

    if (!email) {
        return res.status(400).json({ message: "Email is required" });
    }

    const sql = `UPDATE users 
                 SET otp = NULL, 
                     otp_verified = FALSE 
                 WHERE email = ?`;

    db.query(sql, [email], (err, result) => {
        if (err) {
            console.error("DB Error:", err);
            return res.status(500).json({ message: "Database Error" });
        }

        res.json({ message: "User Logged Out Successfully. OTP Cleared." });
    });
});


app.get("/", (res, req) => {
    res.send("TIG SIM PORTAL BACKEND")
})


app.get("/protected", authenticateToken, (req, res) => {
    const token = req.headers["authorization"];
    if (!token) return res.status(401).json({ message: "No token provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: "Invalid token" });
        res.json({ message: "Protected data accessed", user: decoded.email });
    });
});

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
})