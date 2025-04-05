const jwt = require('jsonwebtoken');
const pool = require('../server'); // adjust to your db connection module

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
        if (err) {

            if (err.name === 'TokenExpiredError') {
                try {
                    const decoded = jwt.decode(token);
                    const email = decoded?.email;

                    if (email) {

                        await pool.query(
                            'UPDATE users SET otp_verified = false, otp = NULL WHERE email = ?',
                            [email]
                        );
                        console.log(`Logged out: ${email} (expired token)`);
                    }
                } catch (dbErr) {
                    console.error("Error clearing OTP after token expiry:", dbErr);
                }

                return res.status(401).json({ message: 'Session expired. Please log in again.' });
            }

            // Invalid token
            return res.status(401).json({ message: 'Invalid token' });
        }


        req.user = user;
        next();
    });
};

module.exports = authenticateToken;
