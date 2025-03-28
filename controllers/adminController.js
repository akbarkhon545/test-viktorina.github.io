// backend/controllers/adminController.js
const User = require('../models/User');
const Question = require('../models/Question');
const XLSX = require('xlsx');
const csv = require('csv-parser');
const { Readable } = require('stream');

exports.listUsers = async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 });
    res.json(users);
  } catch (err) {
    console.error("Foydalanuvchilarni olishda xato:", err);
    res.status(500).send("Server xatosi");
  }
};

exports.importQuestions = async (req, res) => {
  try {
    if (!req.file) return res.status(400).send("Fayl topilmadi");
    const buffer = req.file.buffer;
    const filename = req.file.originalname;
    let questionsData = [];

    if (filename.endsWith('.csv')) {
      const stream = Readable.from(buffer.toString());
      await new Promise((resolve, reject) => {
        stream.pipe(csv())
          .on('data', row => {
            let opts = [];
            for (let i = 1; row[`option${i}`]; i++) {
              opts.push(row[`option${i}`]);
            }
            questionsData.push({
              text: row.text,
              options: opts,
              correctAnswer: parseInt(row.correctAnswer)
            });
          })
          .on('end', resolve)
          .on('error', reject);
      });
    } else if (filename.endsWith('.xlsx')) {
      const workbook = XLSX.read(buffer, { type: 'buffer' });
      const sheet = workbook.Sheets[workbook.SheetNames[0]];
      const rows = XLSX.utils.sheet_to_json(sheet);
      rows.forEach(row => {
        let opts = [];
        for (let i = 1; row[`option${i}`]; i++) {
          opts.push(row[`option${i}`]);
        }
        questionsData.push({
          text: row.text,
          options: opts,
          correctAnswer: parseInt(row.correctAnswer)
        });
      });
    } else {
      return res.status(400).send("Noto'g'ri fayl formati. Faqat CSV yoki XLSX.");
    }

    if (questionsData.length === 0) {
      return res.status(400).send("Faylda savollar topilmadi yoki format mos emas.");
    }
    await Question.insertMany(questionsData);
    res.send("Savollar import qilindi");
  } catch (err) {
    console.error("Savollarni import qilishda xato:", err);
    res.status(500).send("Server xatosi");
  }
};
