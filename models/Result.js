// backend/models/Result.js
const mongoose = require('mongoose');

const resultSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  correctCount: { type: Number, required: true },
  total: { type: Number, required: true },
  scorePercent: { type: Number, required: true },
  mode: { type: String, enum: ['exam', 'practice'], required: true },
  date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Result', resultSchema);
