// backend/controllers/quizController.js
const Question = require('../models/Question');
const Result = require('../models/Result');
const User = require('../models/User');

exports.getQuestions = async (req, res) => {
  try {
    const mode = req.query.mode || 'exam';
    let questions;
    if (mode === 'exam') {
      // Misol uchun, bazadan tasodifiy 10 ta savol tanlash:
      questions = await Question.aggregate([{ $sample: { size: 10 } }]);
    } else {
      // Mashq rejimi: barcha savollarni yoki 20 tagacha savolni qaytarish:
      questions = await Question.aggregate([{ $sample: { size: 20 } }]);
    }
    res.json(questions);
  } catch (err) {
    console.error("Savollarni olishda xato:", err);
    res.status(500).send("Server xatosi");
  }
};

exports.submitAnswers = async (req, res) => {
  try {
    const userId = req.userId; // verifyUser middleware orqali qo'yilgan
    const { answers, mode } = req.body;
    if (!answers || !Array.isArray(answers)) {
      return res.status(400).send("Javoblar yuborilmagan");
    }
    // Foydalanuvchiga yuborgan savollar sonini (frontend savol ro'yxatini kelgan deb faraz qilamiz)
    const questions = await Question.find();
    let correctCount = 0;
    questions.forEach((q, index) => {
      // Agar javob berilgan bo'lsa va u to'g'ri bo'lsa:
      if (answers[index] !== undefined && q.correctAnswer === answers[index]) {
        correctCount++;
      }
    });
    const total = questions.length;
    const scorePercent = total > 0 ? Math.round((correctCount / total) * 100) : 0;
    
    const newResult = new Result({
      user: userId,
      correctCount,
      total,
      scorePercent,
      mode: mode || 'exam'
    });
    await newResult.save();

    // Foydalanuvchi statistikalarini yangilash:
    await User.findByIdAndUpdate(userId, {
      $inc: {
        "stats.quizzesTaken": 1,
        "stats.totalCorrect": correctCount,
        "stats.totalQuestions": total
      }
    });

    res.json({ correctCount, total, scorePercent });
  } catch (err) {
    console.error("Natijani qayta ishlashda xato:", err);
    res.status(500).send("Natijani qayta ishlashda server xatosi");
  }
};
