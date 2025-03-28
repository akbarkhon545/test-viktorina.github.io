// backend/server.js
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const createDefaultAdmin = require('./initAdmin');
require('./config/db');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '..', 'frontend')));

app.use('/api/auth', require('./routes/auth'));
app.use('/api/quiz', require('./routes/quiz'));
app.use('/api/user', require('./routes/user'));
app.use('/api/admin', require('./routes/admin'));

app.use((req, res, next) => {
  if (req.accepts('html')) {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
  } else {
    next();
  }
});

createDefaultAdmin();

app.listen(PORT, () => {
  console.log(`Server ${PORT}-portda ishga tushdi`);
});
