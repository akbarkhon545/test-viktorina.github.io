// backend/routes/user.js
const express = require('express');
const router = express.Router();
const { getProfile, getRankings } = require('../controllers/userController');
const { verifyUser } = require('../middleware/authMiddleware');

// Profil va reyting - faqat tizimga kirgan foydalanuvchi foydalanadi
router.get('/me', verifyUser, getProfile);
router.get('/rankings', verifyUser, getRankings);

module.exports = router;
