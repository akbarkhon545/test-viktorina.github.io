// backend/server.js
require('dotenv').config();           // .env fayldan o'qish
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 5000;

// Ma'lumotlar bazasiga ulanish
require('./config/db');

// Middleware-lar
app.use(express.json());             // JSON body parse qilish
app.use(cookieParser());             // Cookie parse qilish (req.cookies)
// Statik fayllar uchun papka (frontendni xizmat qilish)
app.use(express.static(path.join(__dirname, '..', 'frontend')));
// (Kerak bo'lsa, CSRF himoyasi uchun middleware qo'shish)
// const csurf = require('csurf');
// app.use(csurf({ cookie: { httpOnly: true, sameSite: 'Strict' } }));

// API marshrutlarini ulash
app.use('/api/auth', require('./routes/auth'));
app.use('/api/quiz', require('./routes/quiz'));
app.use('/api/user', require('./routes/user'));
app.use('/api/admin', require('./routes/admin'));

// Foydalanuvchi boshqa yo'lga murojaat qilsa (masalan, biror sahifa yo'q bo'lsa),
// uni index.html ga yo'naltirish (SPA bo'lsa kerak edi, lekin ko'p sahifali bo'lgani uchun shart emas)
app.use((req, res, next) => {
  if (req.accepts('html')) {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
  } else {
    next();
  }
});

// Serverni ishga tushirish
app.listen(PORT, () => {
  console.log(`Server ${PORT}-portda ishga tushdi`);
});
