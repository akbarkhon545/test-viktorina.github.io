// backend/middleware/authMiddleware.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Foydalanuvchini tekshirish middleware
exports.verifyUser = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).send("Avtorizatsiya talab qilinadi");
    }
    // Tokenni tekshirish va dekodlash
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    // (Shuningdek, foydalanuvchi hali mavjudligini bazadan topib tekshirish ham maqsadga muvofiq)
    next();
  } catch (err) {
    console.error("JWT tekshirishda xato:", err);
    return res.status(401).send("Noto'g'ri yoki eskirgan token");
  }
};

// Admin rolini tekshirish (verifyUser dan keyin chaqiriladi)
exports.verifyAdmin = async (req, res, next) => {
  if (!req.userRole || req.userRole !== 'admin') {
    return res.status(403).send("Admin huquqlari talab qilinadi");
  }
  next();
};
