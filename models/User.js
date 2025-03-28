// backend/models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },  // bu yerda hashlangan parol saqlanadi
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  stats: {
    quizzesTaken: { type: Number, default: 0 },      // jami yechilgan testlar
    totalCorrect: { type: Number, default: 0 },      // barcha testlardagi tog'ri javoblar soni
    totalQuestions: { type: Number, default: 0 }     // barcha testlardagi savollar soni
  }
});

module.exports = mongoose.model('User', userSchema);
