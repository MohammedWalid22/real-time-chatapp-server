const mongoose = require('mongoose');
const logger = require('../utils/logger');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      family: 4, // Use IPv4
      // ❌ شيل السطور دي:
      // useNewUrlParser: true,
      // useUnifiedTopology: true,
    });

    logger.info(`✅ MongoDB Connected: ${conn.connection.host}`);

    mongoose.connection.on('error', (err) => {
      logger.error(`MongoDB error: ${err}`);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
    });

  } catch (err) {
    logger.error(`❌ MongoDB Connection Error: ${err.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;