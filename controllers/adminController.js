// backend/controllers/adminController.js
const User = require('../models/User');
const Question = require('../models/Question');
const csv = require('csv-parser'); // Agar CSV fayl parse qilish uchun ishlatsak
const XLSX = require('xlsx');      // Agar Excel (xlsx) fayl parse qilish uchun ishlatsak
const { Readable } = require('stream');

// Foydalanuvchilar ro'yxatini olish (admin panel uchun)
exports.listUsers = async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 }); // barcha foydalanuvchilar, parolsiz
    res.json(users);
  } catch (err) {
    console.error("Foydalanuvchilarni olishda xato:", err);
    res.status(500).send("Server xatosi");
  }
};

// Savollarni import qilish (CSV yoki Excel fayl orqali)
exports.importQuestions = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).send("Fayl topilmadi");
    }
    const buffer = req.file.buffer;
    const filename = req.file.originalname;
    let questionsData = [];

    if (filename.endsWith('.csv')) {
      // CSV faylni o'qish
      const stream = Readable.from(buffer.toString());
      await new Promise((resolve, reject) => {
        stream.pipe(csv())
          .on('data', (row) => {
            // CSV fayl strukturasiga qarab maydonlarni nomlash
            // Masalan, CSV ustun nomlari: text, option1, option2, option3, option4, correctAnswer
            const opts = [];
            // row.option1, row.option2, ... mavjud deb faraz qilamiz
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
      // Excel faylni o'qish
      const workbook = XLSX.read(buffer, { type: 'buffer' });
      const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
      const rows = XLSX.utils.sheet_to_json(firstSheet);
      // Exceldagi ustun nomlari ham xuddi CSV dagidek text, option1, ... deb faraz qilamiz
      rows.forEach(row => {
        const opts = [];
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

    // Olingan questionData massivini bazaga yozish
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
