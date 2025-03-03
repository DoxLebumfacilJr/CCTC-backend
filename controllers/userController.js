const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { User } = require("../models");

// Register User
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword });
    res.status(201).json({ message: "User registered successfully", user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Login User
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });

    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user.id }, "secret", { expiresIn: "1h" });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Add User
exports.addUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword });
    res.status(201).json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Update User
exports.updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email } = req.body;
    await User.update({ name, email }, { where: { id } });
    res.json({ message: "User updated successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Delete User
exports.deleteUser = async (req, res) => {
  try {
    const { id } = req.params;
    await User.destroy({ where: { id } });
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
