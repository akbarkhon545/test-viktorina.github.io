// backend/routes/auth.js
const express = require('express');
const router = express.Router();
const { register, login } = require('../controllers/authController');

// Ro'yxatdan o'tish (yangi foydalanuvchi yaratish)
router.post('/register', register);

// Tizimga kirish (mavjud foydalanuvchi)
router.post('/login', login);

module.exports = router;
