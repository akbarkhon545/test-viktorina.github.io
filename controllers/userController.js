// backend/controllers/userController.js
const User = require('../models/User');
const Result = require('../models/Result');

// Joriy foydalanuvchi profili
exports.getProfile = async (req, res) => {
  try {
    const userId = req.userId;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send("Foydalanuvchi topilmadi");
    }
    // Parolni jo'natmaslik uchun user obyektdan passwordni olib tashlaymiz
    const userData = {
      name: user.name,
      email: user.email,
      role: user.role,
      stats: user.stats
    };
    res.json(userData);
  } catch (err) {
    console.error("Profilni olishda xato:", err);
    res.status(500).send("Server xatosi");
  }
};

// Reytingdagi eng yaxshi foydalanuvchilar ro'yxati
exports.getRankings = async (req, res) => {
  try {
    // Eng yuqori natija foizi bo'yicha top 10 foydalanuvchini olish
    // Oddiy yo'l: Result kolleksiyasidan har bir foydalanuvchining eng yuqori scorePercent ni topamiz
    const topResults = await Result.aggregate([
      { $group: { _id: "$user", maxScore: { $max: "$scorePercent" } } },
      { $sort: { maxScore: -1 } },
      { $limit: 10 }
    ]);
    // topResults endi [{ _id: userId, maxScore: 95 }, {...}] shaklida
    // Bu foydalanuvchi ma'lumotlarini olib kelamiz
    const userIds = topResults.map(r => r._id);
    const users = await User.find({ _id: { $in: userIds } });
    // Foydalanuvchi ismi va maxScore ni birlashtirish
    const ranking = topResults.map(r => {
      const user = users.find(u => u._id.toString() === r._id.toString());
      return {
        name: user ? user.name : "Noma'lum",
        email: user ? user.email : "",
        highScore: r.maxScore
      };
    });
    res.json(ranking);
  } catch (err) {
    console.error("Reytingni olishda xato:", err);
    res.status(500).send("Server xatosi");
  }
};
