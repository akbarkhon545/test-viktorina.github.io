// backend/config/db.js
const mongoose = require('mongoose');

const dbURI = process.env.MONGO_URI || 'mongodb://localhost:27017/quizapp';
mongoose.connect(dbURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log("MongoDB bazasiga ulanildi");
}).catch(err => {
  console.error("MongoDB ulanish xatosi:", err);
});

module.exports = mongoose;
