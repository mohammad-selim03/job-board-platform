import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const uri = process.env.MONGODB_URI || "mongodb://localhost:27017/jobPortal";
mongoose
  .connect(uri)
  .then(() => console.log("MongoDB connection established successfully"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Import routes
import usersRouter from "./routes/users.js";
import jobsRouter from "./routes/jobs.js";
import applicationsRouter from "./routes/applications.js";

// Use routes
app.use("/api/users", usersRouter);
app.use("/api/jobs", jobsRouter);
app.use("/api/applications", applicationsRouter);

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
