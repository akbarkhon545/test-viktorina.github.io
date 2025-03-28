// backend/routes/quiz.js
const express = require('express');
const router = express.Router();
const { getQuestions, submitAnswers } = require('../controllers/quizController');
const { verifyUser } = require('../middleware/authMiddleware');

router.get('/questions', verifyUser, getQuestions);
router.post('/submit', verifyUser, submitAnswers);

module.exports = router;
