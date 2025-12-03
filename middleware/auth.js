const jwt = require('jsonwebtoken');
require('dotenv').config();

function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Token tidak ditemukan" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Token tidak valid" });
        req.user = user;
        next();
    });
}

function authorizeRole(role) {
    return (req, res, next) => {
        if (req.user.user.role !== role) {
            return res.status(403).json({ error: "Akses ditolak" });
        }
        next();
    };
}

module.exports = { authenticateToken, authorizeRole };
