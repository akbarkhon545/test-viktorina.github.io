// backend/controllers/quizController.js
const Question = require('../models/Question');
const Result = require('../models/Result');
const User = require('../models/User');

// Savollarni olish (mode ga qarab filtr yoki tasodifiylashtirish mumkin)
exports.getQuestions = async (req, res) => {
  try {
    const mode = req.query.mode || 'exam';
    let questions;
    if (mode === 'exam') {
      // Imtihon rejimi: masalan, bazadan tasodifiy 10 ta savolni tanlash
      const count = await Question.countDocuments();
      const randomSkip = Math.max(0, Math.floor(Math.random() * (count - 10)));
      questions = await Question.find().skip(randomSkip).limit(10);
    } else {
      // Mashq rejimi: bazadagi barcha yoki ko'proq savollarni qaytarish
      questions = await Question.find().limit(20);
    }
    res.json(questions);
  } catch (err) {
    console.error("Savollarni olishda xato:", err);
    res.status(500).send("Savollarni olishda server xatosi");
  }
};

// Foydalanuvchi javoblarini qabul qilish va natija qaytarish
exports.submitAnswers = async (req, res) => {
  try {
    const userId = req.userId;  // verifyUser middleware tufayli mavjud
    const { answers, mode } = req.body;
    if (!answers || !Array.isArray(answers)) {
      return res.status(400).send("Javoblar yuborilmagan");
    }
    // Bazadan barcha savollarni tartib bilan olib, tekshiramiz
    const questions = await Question.find();  // (yaxshiroq: IDlar orqali faqat keraklilarni olish)
    let correctCount = 0;
    questions.forEach((q, index) => {
      if (answers[index] !== undefined && q.correctAnswer === answers[index]) {
        correctCount++;
      }
    });
    const total = questions.length;
    const scorePercent = Math.round((correctCount / total) * 100);

    // Result ni bazaga saqlash (foydalanuvchi statistikasi ham yangilanadi)
    const newResult = new Result({
      user: userId,
      correctCount,
      total,
      scorePercent,
      mode: mode || 'exam'
    });
    await newResult.save();
    // Foydalanuvchi statistikani yangilash (jami to'g'ri va savollar soni)
    await User.findByIdAndUpdate(userId, {
      $inc: {
        "stats.quizzesTaken": 1,
        "stats.totalCorrect": correctCount,
        "stats.totalQuestions": total
      }
    });
    // Foydalanuvchiga javob qaytarish (to'g'ri soni, foiz, jami)
    res.json({
      correctCount: correctCount,
      total: total,
      scorePercent: scorePercent
    });
  } catch (err) {
    console.error("Natijani qayta ishlashda xato:", err);
    res.status(500).send("Natijani qayta ishlashda server xatosi");
  }
};
