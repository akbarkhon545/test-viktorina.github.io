// backend/controllers/authController.js
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key';
const JWT_EXPIRES = '1h';

exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).send("Bu email bilan foydalanuvchi allaqachon mavjud");
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();
    res.status(201).send("Foydalanuvchi ro'yxatga olindi");
  } catch (err) {
    console.error("Register xato:", err);
    res.status(500).send("Server xatosi");
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send("Email yoki parol noto'g'ri");
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send("Email yoki parol noto'g'ri");
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );
    res.cookie('token', token, {
      httpOnly: true,
      secure: false, // Production: true with HTTPS
      sameSite: 'Strict'
    });
    res.send("Login muvaffaqiyatli");
  } catch (err) {
    console.error("Login xato:", err);
    res.status(500).send("Server xatosi");
  }
};
