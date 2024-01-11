const joi = require("joi");
const { model, Schema } = require("mongoose");

const userBodySchema = joi.object({
  email: joi
    .string()
    .email()
    .required()
    .messages({ "any.required": "missing required email field " }),
  password: joi.string().min(6).required(),
  subscription: joi.string().allow("starter", "pro", "business"),
});

const verifyEmailSchema = joi.object({
  email: joi
    .string()
    .email()
    .required()
    .messages({ "any.required": "missing required email field " }),
});

const usersSchema = new Schema({
  password: {
    type: String,
    required: [true, "Set password for user"],
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
  },
  subscription: {
    type: String,
    enum: ["starter", "pro", "business"],
    default: "starter",
  },
  token: String,
  avatarURL: String,
  verify: {
    type: Boolean,
    default: false,
  },
  verificationToken: {
    type: String,
    required: [true, "Verify token is required"],
  },
});

const User = model("user", usersSchema);

module.exports = {
  userBodySchema,
  verifyEmailSchema,
  User,
};
