// backend/controllers/authController.js
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
const JWT_EXPIRES = '1h';  // token amal qilish muddati (masalan, 1 soat)

// Ro'yxatdan o'tish funksiyasi
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    // Email oldin ro'yxatdan o'tganligini tekshirish
    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).send("Bu email bilan foydalanuvchi allaqachon mavjud");
    }
    // Parolni hash qilish
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    // Yangi foydalanuvchi yaratish
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();
    return res.status(201).send("Foydalanuvchi ro'yxatga olindi");
  } catch (err) {
    console.error("Register xato:", err);
    res.status(500).send("Server xatosi");
  }
};

// Tizimga kirish funksiyasi
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send("Email yoki parol noto'g'ri");
    }
    // Parolni tekshirish
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send("Email yoki parol noto'g'ri");
    }
    // JWT token yaratish (payload ichida foydalanuvchi ID va roli)
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );
    // Tokenni HttpOnly cookie sifatida jo'natish
    res.cookie('token', token, {
      httpOnly: true,
      secure: false,      // faqat HTTPS orqali jo'natish (prod muhitda true)
      sameSite: 'Strict'  // CSRFdan himoya uchun Strict, agar boshqa domain bo'lsa 'Lax' ko'rib chiqish mumkin
    });
    // Foydalanuvchiga javob
    res.send("Login muvaffaqiyatli");
  } catch (err) {
    console.error("Login xato:", err);
    res.status(500).send("Server xatosi");
  }
};
