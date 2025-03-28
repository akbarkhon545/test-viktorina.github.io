// backend/middleware/authMiddleware.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key';

exports.verifyUser = (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).send("Avtorizatsiya talab qilinadi");
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch (err) {
    console.error("JWT tekshirishda xato:", err);
    return res.status(401).send("Noto'g'ri yoki eskirgan token");
  }
};

exports.verifyAdmin = (req, res, next) => {
  if (req.userRole !== 'admin') {
    return res.status(403).send("Admin huquqlari talab qilinadi");
  }
  next();
};
