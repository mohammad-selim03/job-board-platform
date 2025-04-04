import { Router } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import { auth, mockUsers } from "../middleware/auth.js";

const router = Router();

// Register a new user
router.post("/register", async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;

    // Validate input
    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check if user exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      role: "user", // Default role
    });

    const savedUser = await newUser.save();

    // Create token
    const token = jwt.sign(
      { id: savedUser._id.toString(), role: savedUser.role },
      process.env.JWT_SECRET || "your_jwt_secret",
      { expiresIn: "1d" }
    );

    res.status(201).json({
      token,
      user: {
        id: savedUser._id,
        email: savedUser.email,
        firstName: savedUser.firstName,
        lastName: savedUser.lastName,
        role: savedUser.role,
        profileImage: savedUser.profileImage,
      },
    });
  } catch (error) {
    console.error("Registration error:", error.message);
    res.status(500).json({ message: "Error creating user" });
  }
});

// Login user
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    // Check mock users first
    const mockUser = Object.values(mockUsers).find(
      (user) => user.email === email
    );
    if (mockUser && password === mockUser.password) {
      const token = jwt.sign(
        { id: mockUser.id, role: mockUser.role },
        process.env.JWT_SECRET || "your_jwt_secret",
        { expiresIn: "1d" }
      );

      return res.json({
        token,
        user: {
          id: mockUser.id,
          email: mockUser.email,
          firstName: mockUser.firstName,
          lastName: mockUser.lastName,
          role: mockUser.role,
          profileImage: mockUser.profileImage,
        },
      });
    }

    // Find real user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Create token
    const token = jwt.sign(
      { id: user._id.toString(), role: user.role },
      process.env.JWT_SECRET || "your_jwt_secret",
      { expiresIn: "1d" }
    );

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        profileImage: user.profileImage,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ message: "Error during login" });
  }
});

// Get user profile
router.get("/profile", auth, async (req, res) => {
  try {
    // Check if it's a mock user
    if (req.user.id.startsWith("mock-")) {
      const mockUsers = {
        "mock-candidate-id": {
          id: "mock-candidate-id",
          email: "candidate@example.com",
          firstName: "John",
          lastName: "Candidate",
          role: "user",
          profileImage: null,
        },
        "mock-employer-id": {
          id: "mock-employer-id",
          email: "employer@example.com",
          firstName: "Jane",
          lastName: "Employer",
          role: "employer",
          profileImage: null,
        },
        "mock-admin-id": {
          id: "mock-admin-id",
          email: "admin@example.com",
          firstName: "Admin",
          lastName: "User",
          role: "admin",
          profileImage: null,
        },
      };

      const mockUser = mockUsers[req.user.id];
      if (mockUser) {
        return res.json(mockUser);
      }
    }

    // For real users
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update user profile
router.put("/profile", auth, async (req, res) => {
  try {
    // Check if it's a mock user
    if (req.user.id.startsWith("mock-")) {
      return res
        .status(403)
        .json({ message: "Cannot update mock user profiles" });
    }

    // For real users
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Update fields
    const { firstName, lastName, profileImage } = req.body;
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (profileImage) user.profileImage = profileImage;

    await user.save();

    res.json({
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        profileImage: user.profileImage,
      },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

export default router;
