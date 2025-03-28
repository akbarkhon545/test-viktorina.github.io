// backend/controllers/userController.js
const User = require('../models/User');
const Result = require('../models/Result');

exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).send("Foydalanuvchi topilmadi");
    res.json({ name: user.name, email: user.email, role: user.role, stats: user.stats });
  } catch (err) {
    console.error("Profilni olishda xato:", err);
    res.status(500).send("Server xatosi");
  }
};

exports.getRankings = async (req, res) => {
  try {
    const topResults = await Result.aggregate([
      { $group: { _id: "$user", maxScore: { $max: "$scorePercent" } } },
      { $sort: { maxScore: -1 } },
      { $limit: 10 }
    ]);
    // Bu yerda foydalanuvchi ma'lumotlarini qo'shib, reytingni tuzing
    res.json(topResults);
  } catch (err) {
    console.error("Reytingni olishda xato:", err);
    res.status(500).send("Server xatosi");
  }
};
