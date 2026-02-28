const Joi = require('joi');

exports.registerSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .required(),
  email: Joi.string()
    .email()
    .required(),
  password: Joi.string()
    .min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain uppercase, lowercase, number and special character'
    })
});

exports.loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
  twoFactorCode: Joi.string().length(6).optional()
});

exports.messageSchema = Joi.object({
  roomId: Joi.string().required(),
  content: Joi.string().max(5000).required(),
  type: Joi.string().valid('text', 'image', 'video', 'audio', 'voice').default('text'),
  replyTo: Joi.string().optional()
});