const { createClient } = require('redis');
const logger = require('../utils/logger');

class RedisClient {
  constructor() {
    this.client = null;
    this.isConnected = false;
  }

  async connect() {
    try {
      this.client = createClient({
        url: process.env.REDIS_URL || 'redis://localhost:6379',
        socket: {
          reconnectStrategy: (retries) => {
            if (retries > 10) {
              logger.error('Redis max reconnection attempts reached');
              return new Error('Max retries');
            }
            return Math.min(retries * 100, 3000);
          }
        }
      });

      this.client.on('connect', () => {
        logger.info('🔌 Redis connecting...');
      });

      this.client.on('ready', () => {
        this.isConnected = true;
        logger.info('✅ Redis connected and ready');
      });

      this.client.on('error', (err) => {
        logger.error('Redis error:', err);
        this.isConnected = false;
      });

      this.client.on('reconnecting', () => {
        logger.warn('Redis reconnecting...');
      });

      this.client.on('end', () => {
        logger.warn('Redis connection closed');
        this.isConnected = false;
      });

      await this.client.connect();

    } catch (error) {
      logger.error('Failed to connect to Redis:', error);
      // Don't throw - app can work without Redis
    }
  }

  // Cache operations
  async get(key) {
    if (!this.isConnected) return null;
    try {
      return await this.client.get(key);
    } catch (error) {
      logger.error('Redis get error:', error);
      return null;
    }
  }

  async set(key, value, expireSeconds = 3600) {
    if (!this.isConnected) return false;
    try {
      await this.client.setEx(key, expireSeconds, value);
      return true;
    } catch (error) {
      logger.error('Redis set error:', error);
      return false;
    }
  }

  async del(key) {
    if (!this.isConnected) return false;
    try {
      await this.client.del(key);
      return true;
    } catch (error) {
      logger.error('Redis del error:', error);
      return false;
    }
  }

  // Hash operations
  async hGet(key, field) {
    if (!this.isConnected) return null;
    try {
      return await this.client.hGet(key, field);
    } catch (error) {
      logger.error('Redis hGet error:', error);
      return null;
    }
  }

  async hSet(key, field, value) {
    if (!this.isConnected) return false;
    try {
      await this.client.hSet(key, field, value);
      return true;
    } catch (error) {
      logger.error('Redis hSet error:', error);
      return false;
    }
  }

  // List operations
  async lPush(key, value) {
    if (!this.isConnected) return false;
    try {
      await this.client.lPush(key, value);
      return true;
    } catch (error) {
      logger.error('Redis lPush error:', error);
      return false;
    }
  }

  async lRange(key, start, stop) {
    if (!this.isConnected) return [];
    try {
      return await this.client.lRange(key, start, stop);
    } catch (error) {
      logger.error('Redis lRange error:', error);
      return [];
    }
  }

  // Set operations
  async sAdd(key, value) {
    if (!this.isConnected) return false;
    try {
      await this.client.sAdd(key, value);
      return true;
    } catch (error) {
      logger.error('Redis sAdd error:', error);
      return false;
    }
  }

  async sMembers(key) {
    if (!this.isConnected) return [];
    try {
      return await this.client.sMembers(key);
    } catch (error) {
      logger.error('Redis sMembers error:', error);
      return [];
    }
  }

  // Sorted set operations (for rate limiting)
  async zAdd(key, score, member) {
    if (!this.isConnected) return false;
    try {
      await this.client.zAdd(key, { score, value: member });
      return true;
    } catch (error) {
      logger.error('Redis zAdd error:', error);
      return false;
    }
  }

  async zRemRangeByScore(key, min, max) {
    if (!this.isConnected) return 0;
    try {
      return await this.client.zRemRangeByScore(key, min, max);
    } catch (error) {
      logger.error('Redis zRemRangeByScore error:', error);
      return 0;
    }
  }

  async zCard(key) {
    if (!this.isConnected) return 0;
    try {
      return await this.client.zCard(key);
    } catch (error) {
      logger.error('Redis zCard error:', error);
      return 0;
    }
  }

  // Pub/Sub for real-time features
  async publish(channel, message) {
    if (!this.isConnected) return false;
    try {
      await this.client.publish(channel, message);
      return true;
    } catch (error) {
      logger.error('Redis publish error:', error);
      return false;
    }
  }

  subscribe(channel, callback) {
    if (!this.isConnected) return false;
    
    const subscriber = this.client.duplicate();
    subscriber.connect().then(() => {
      subscriber.subscribe(channel, (message) => {
        callback(message);
      });
    });
    
    return true;
  }

  // Session management
  async saveSession(sessionId, data, expireSeconds = 86400) {
    return this.set(`session:${sessionId}`, JSON.stringify(data), expireSeconds);
  }

  async getSession(sessionId) {
    const data = await this.get(`session:${sessionId}`);
    return data ? JSON.parse(data) : null;
  }

  async deleteSession(sessionId) {
    return this.del(`session:${sessionId}`);
  }

  // Online status
  async setUserOnline(userId, socketId) {
    await this.set(`online:${userId}`, socketId, 300); // 5 minutes TTL
    await this.sAdd('online_users', userId);
  }

  async setUserOffline(userId) {
    await this.del(`online:${userId}`);
    // Note: sRem not available in redis v4, use set difference
  }

  async isUserOnline(userId) {
    const exists = await this.get(`online:${userId}`);
    return exists !== null;
  }

  async getOnlineUsers() {
    return this.sMembers('online_users');
  }

  // Rate limiting
  async checkRateLimit(key, maxRequests, windowSeconds) {
    const now = Date.now();
    const windowStart = now - (windowSeconds * 1000);
    
    // Remove old entries
    await this.zRemRangeByScore(key, 0, windowStart);
    
    // Count current entries
    const count = await this.zCard(key);
    
    if (count >= maxRequests) {
      return { allowed: false, remaining: 0 };
    }
    
    // Add current request
    await this.zAdd(key, now, `${now}-${Math.random()}`);
    
    return { allowed: true, remaining: maxRequests - count - 1 };
  }

  // Disconnect
  async disconnect() {
    if (this.client) {
      await this.client.quit();
      this.isConnected = false;
      logger.info('Redis disconnected');
    }
  }
}

// Singleton instance
const redisClient = new RedisClient();

module.exports = redisClient;