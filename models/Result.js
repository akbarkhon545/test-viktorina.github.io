// backend/models/Result.js
const mongoose = require('mongoose');

const resultSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  correctCount: { type: Number, required: true },   // to'g'ri javoblar soni
  total: { type: Number, required: true },          // jami savollar soni
  scorePercent: { type: Number, required: true },   // (correctCount/total*100) foiz ko'rsatkich
  mode: { type: String, enum: ['exam', 'practice'], required: true },
  date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Result', resultSchema);
