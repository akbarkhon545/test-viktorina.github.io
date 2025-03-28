// backend/models/Question.js
const mongoose = require('mongoose');

const questionSchema = new mongoose.Schema({
  text: { type: String, required: true },
  options: { type: [String], required: true },
  // correctAnswer is stored as the index (0-based) of the correct option
  correctAnswer: { type: Number, required: true }
});

module.exports = mongoose.model('Question', questionSchema);
