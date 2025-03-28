// backend/initAdmin.js
const User = require('./models/User');
const bcrypt = require('bcrypt');

async function createDefaultAdmin() {
  try {
    const adminEmail = "akbarkhon545@gmail.com";
    const adminPassword = "a19791984f";
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (!existingAdmin) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(adminPassword, salt);
      const adminUser = new User({
        name: "Administrator",
        email: adminEmail,
        password: hashedPassword,
        role: "admin"
      });
      await adminUser.save();
      console.log("Default admin hisobi yaratildi.");
    } else {
      console.log("Admin hisobi allaqachon mavjud.");
    }
  } catch (err) {
    console.error("Default admin hisobini yaratishda xato:", err);
  }
}

module.exports = createDefaultAdmin;
