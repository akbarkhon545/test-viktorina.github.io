// backend/routes/admin.js
const express = require('express');
const router = express.Router();
const { importQuestions, listUsers } = require('../controllers/adminController');
const { verifyUser, verifyAdmin } = require('../middleware/authMiddleware');
const multer = require('multer');
const upload = multer(); // memory storage (yuklangan faylni xotirada ushlab turish)

router.get('/users', verifyUser, verifyAdmin, listUsers);
router.post('/import', verifyUser, verifyAdmin, upload.single('file'), importQuestions);

module.exports = router;
