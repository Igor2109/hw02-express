const jimp = require("jimp");
const express = require("express");

const bcrypt = require("bcryptjs");

const jwt = require("jsonwebtoken");

const fs = require("fs/promises");

const path = require("path");

const avatarsPath = path.resolve("public", "avatars");

const gravatar = require("gravatar");

const { userBodySchema, User } = require("../../models/users");
const { authenticate } = require("../../middlewares/authenticate");
const upload = require("../../middlewares/upload");

const router = express.Router();

router.post("/register", async (req, res, next) => {
  const body = req.body;
  if (Object.keys(body).length === 0) {
    res.status(400).json({ message: "missing fields" });
    return;
  }
  const { error } = userBodySchema.validate(body);
  if (error) {
    res.status(400).json({ message: error.details[0].message });
    return;
  }
  const isExist = await User.exists({
    email: body.email,
  });
  if (isExist) {
    res.status(409).json({ message: "Email in use" });
    return;
  }
  const hashPassword = await bcrypt.hash(body.password, 10);

  const secureAvatarUrl = gravatar.url(
    body.email,
    { s: "250", r: "x", d: "retro" },
    true
  );
  const user = await User.create({
    ...body,
    password: hashPassword,
    avatarURL: secureAvatarUrl,
  });
  res
    .status(201)
    .json({ user: { email: user.email, subscription: user.subscription } });
});

router.post("/login", async (req, res, next) => {
  const body = req.body;
  if (Object.keys(body).length === 0) {
    res.status(400).json({ message: "missing fields" });
    return;
  }
  const { error } = userBodySchema.validate(body);
  if (error) {
    res.status(400).json({ message: error.details[0].message });
    return;
  }
  const user = await User.findOne({ email: body.email });

  if (!user) {
    res.status(401).json({ message: "User with such email is't registered!" });
    return;
  }

  const passwordCompare = await bcrypt.compare(body.password, user.password);

  if (!passwordCompare) {
    res.status(401).json({ message: "Email or password is wrong" });
    return;
  }
  const payload = { _id: user._id };
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "23h" });
  await User.findByIdAndUpdate(user._id, { token });
  res.status(200).json({
    token,
    user: {
      email: user.email,
      subscription: user.subscription,
      avatarURL: user.avatarURL,
    },
  });
});

router.post("/logout", authenticate, async (req, res, next) => {
  const { _id } = req.user;
  await User.findByIdAndUpdate(_id, { token: "" });
  res.status(204).json();
});

router.get("/current", authenticate, async (req, res, next) => {
  const { email, subscription } = req.user;

  res.json({ email, subscription });
});

router.patch(
  "/avatars",
  authenticate,
  upload.single("avatar"),
  async (req, res, next) => {
    const user = req.user;

    if (!req.file) {
      res
        .status(400)
        .json({ message: 'Please add avatar image to field "avatar"' });
      return;
    }
    const newPath = path.join(avatarsPath, req.file.filename);
    const oldPath = req.file.path;
    await fs.rename(oldPath, newPath);
    jimp.read(newPath, (err, selectedFile) => {
      if (err) throw err;
      selectedFile.resize(250, 250).write(newPath);
    });
    const userAvatarPath = path.join("avatars", req.file.filename);
    await User.updateOne({ _id: user._id }, { avatarURL: userAvatarPath });
    res.status(200).json({ avatarURL: userAvatarPath });
  }
);

module.exports = router;