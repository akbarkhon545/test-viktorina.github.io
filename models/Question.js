// backend/models/Question.js
const mongoose = require('mongoose');

const questionSchema = new mongoose.Schema({
  text: { type: String, required: true },             // savol matni
  options: { type: [String], required: true },        // javob variantlari ro'yxati
  correctAnswer: { type: Number, required: true }     // to'g'ri javob indeksi (options ichida 0-based)
  // Agar kerak bo'lsa, bu yerga mavzu/kategoriya, murakkablik darajasi kabi maydonlar qo'shish mumkin.
});

module.exports = mongoose.model('Question', questionSchema);
