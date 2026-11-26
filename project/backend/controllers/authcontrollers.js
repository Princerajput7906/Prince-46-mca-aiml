const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== "string" ||
      !name.trim() ||
      typeof email !== "string" ||
      !email.trim() ||
      typeof password !== "string" ||
      password.length < 8
    ) {
      return res.status(400).json({
        message: "Name, valid email, and password of at least 8 characters are required.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const [existingUsers] = await db.execute(
      "SELECT id FROM users WHERE email = ?",
      [normalizedEmail]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({
        message: "Email already registered.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.execute(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name.trim(), normalizedEmail, hashedPassword]
    );

    return res.status(201).json({
      message: "Signup successful. Please log in.",
    });
  } catch (error) {
    console.error("Signup error:", error.message);

    return res.status(500).json({
      message: "Something went wrong.",
    });
  }
}


const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        message: "Email and password are required.",
      });
    }

    const [users] = await db.execute(
      "SELECT id, name, email, password FROM users WHERE email = ?",
      [email.trim().toLowerCase()]
    );

    if (users.length === 0) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const user = users[0];

    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.json({
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      message: "Something went wrong.",
    });
  }
}


module.exports = {signup, login}