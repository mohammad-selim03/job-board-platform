import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

// Mock users for development
export const mockUsers = {
  "candidate@example.com": {
    id: "mock-candidate-id",
    email: "candidate@example.com",
    firstName: "John",
    lastName: "Candidate",
    role: "user",
    profileImage: null,
    password: "password123",
  },
  "employer@example.com": {
    id: "mock-employer-id",
    email: "employer@example.com",
    firstName: "Jane",
    lastName: "Employer",
    role: "employer",
    profileImage: null,
    password: "password123",
  },
  "admin@example.com": {
    id: "mock-admin-id",
    email: "admin@example.com",
    firstName: "Admin",
    lastName: "User",
    role: "admin",
    profileImage: null,
    password: "admin123",
  },
};

// Middleware to authenticate user
export const auth = async (req, res, next) => {
  try {
    // Check if authorization header exists
    if (!req.headers.authorization) {
      return res.status(401).json({ message: "No authorization header" });
    }

    // Get token from header
    const authHeader = req.headers.authorization;
    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Invalid authorization format" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || "your_jwt_secret");
    } catch (error) {
      console.error("Token verification error:", error.message);
      return res.status(401).json({ message: "Invalid token" });
    }

    // Check if it's a mock user
    if (decoded.id.startsWith("mock-")) {
      const mockUser = Object.values(mockUsers).find(
        (user) => user.id === decoded.id
      );
      if (mockUser) {
        req.user = {
          id: mockUser.id,
          role: mockUser.role,
        };
        return next();
      }
    }

    // For real users, verify against database
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    req.user = {
      id: user._id,
      role: user.role,
    };

    next();
  } catch (error) {
    console.error("Authentication error:", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Check if user is admin
export const isAdmin = async (req, res, next) => {
  try {
    // Check mock users first
    if (req.user.id.startsWith("mock-")) {
      const mockUser = Object.values(mockUsers).find(
        (user) => user.id === req.user.id
      );
      if (mockUser && mockUser.role === "admin") {
        return next();
      }
      return res.status(403).json({ message: "Access denied, admin only" });
    }

    // Check real users
    const user = await User.findById(req.user.id);
    if (!user || user.role !== "admin") {
      return res.status(403).json({ message: "Access denied, admin only" });
    }
    next();
  } catch (error) {
    console.error("Admin authorization error:", error.message);
    res.status(500).json({ message: error.message });
  }
};

// Check if user is employer or admin
export const isEmployerOrAdmin = async (req, res, next) => {
  try {
    // Check mock users first
    if (req.user.id.startsWith("mock-")) {
      const mockUser = Object.values(mockUsers).find(
        (user) => user.id === req.user.id
      );
      if (
        mockUser &&
        (mockUser.role === "employer" || mockUser.role === "admin")
      ) {
        return next();
      }
      return res
        .status(403)
        .json({ message: "Access denied, employer or admin only" });
    }

    // Check real users
    const user = await User.findById(req.user.id);
    if (!user || (user.role !== "employer" && user.role !== "admin")) {
      return res
        .status(403)
        .json({ message: "Access denied, employer or admin only" });
    }
    next();
  } catch (error) {
    console.error("Employer authorization error:", error.message);
    res.status(500).json({ message: error.message });
  }
};

// Mock authentication for demo purposes
// This will allow frontend testing without a running backend
export const mockAuth = (req, res, next) => {
  // This is only for development and should be removed in production
  if (req.method === "POST" && req.path === "/users/login") {
    const { email, password } = req.body;
    const user = mockUsers[email];

    if (user && password === user.password) {
      // Simulate successful login
      const token = jwt.sign(
        { id: user.id, role: user.role },
        process.env.JWT_SECRET || "your_jwt_secret",
        { expiresIn: "1d" }
      );

      return res.json({ token, user });
    } else {
      return res.status(400).json({ message: "Invalid email or password" });
    }
  }

  if (req.method === "GET" && req.path === "/users/profile") {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res
        .status(401)
        .json({ message: "No token, authorization denied" });
    }

    try {
      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET || "your_jwt_secret"
      );
      // Find the mock user
      const user = Object.values(mockUsers).find((u) => u.id === decoded.id);
      if (user) {
        return res.json(user);
      }
    } catch (error) {
      // Token verification failed
    }
  }

  // Continue to actual implementation if not handled by mock
  next();
};
