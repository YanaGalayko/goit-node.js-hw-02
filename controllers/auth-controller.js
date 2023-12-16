import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import gravatar from "gravatar";
import path from "path";
import jimp from "jimp";
import fs from "fs/promises";
import { nanoid } from "nanoid";
import User from "../models/User.js";
import { HttpError } from "../utils/helpers/HttpError.js";
import sendEmail from "../utils/helpers/sendEmail.js";

const { JWT_SECRET, BASE_URL } = process.env;
const avatarPath = path.resolve("public", "avatars");

const register = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      return next(HttpError(409, "Email already exist"));
    }

    const avatarURL = gravatar.url(email);
    const hashPassword = await bcrypt.hash(password, 10);
    const verificationToken = nanoid();
    const newUser = await User.create({
      ...req.body,
      avatarURL,
      password: hashPassword,
      verificationToken,
    });

    const verifyEmail = {
      to: email,
      subject: "Verify email",
      html: `<a target="_blank" href="${BASE_URL}/users/verify/${verificationToken}">Click verify email</a>`,
    };
    await sendEmail(verifyEmail);

    res.status(201).json({
      user: {
        email: newUser.email,
        avatarURL: newUser.avatarURL,
        subscription: newUser.subscription,
      },
    });
  } catch (error) {
    next(error);
  }
};

const verify = async (req, res, next) => {
  try {
    const { verificationToken } = req.params;
    const user = await User.findOne({ verificationToken });
    if (!user) {
      return next(HttpError(404, "User not found"));
    }

    await User.findByIdAndUpdate(user._id, {
      verify: true,
      verificationToken: "_",
    });

    res.json({
      message: "Verification successful",
    });
  } catch (error) {
    next(error);
  }
};

const resendVerify = async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return next(HttpError(401, "Email not found"));
    }

    if (user.verify) {
      return next(HttpError(400, "Verification has already been passed"));
    }

    const verifyEmail = {
      to: email,
      subject: "Verify email",
      html: `<a target="_blank" href="${BASE_URL}/users/verify/${user.verificationToken}">Click verify email</a>`,
    };

    await sendEmail(verifyEmail);

    res.json({
      message: "Verification email sent",
    });
  } catch (error) {
    next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return next(HttpError(401, "Email or password is wrong"));
    }
    if (!user.verify) {
      return next(HttpError(401, "Email not verify"));
    }
    const passwordCompare = await bcrypt.compare(password, user.password);
    if (!passwordCompare) {
      return next(HttpError(401, "Email or password is wrong"));
    }

    const payload = { id: user._id };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "23h" });
    await User.findByIdAndUpdate(user._id, { token });

    res.json({
      token,
      user: { email: user.email, subscription: user.subscription },
    });
  } catch (error) {
    next(error);
  }
};

const getCurrent = async (req, res, next) => {
  try {
    const { email, subscription } = req.user;
    res.json({ email, subscription });
  } catch (error) {
    next(error);
  }
};

const logout = async (req, res, next) => {
  try {
    const { _id } = req.user;
    await User.findByIdAndUpdate(_id, { token: "" });

    res.status(204).json();
  } catch (error) {
    next(error);
  }
};

const subscription = async (req, res, next) => {
  try {
    const { email } = req.user;
    const result = await User.findOneAndUpdate({ email }, req.body);
    res.json({
      email: result.email,
      subscription: result.subscription,
    });
  } catch (error) {
    next(error);
  }
};

const updateAvatar = async (req, res, next) => {
  try {
    const { _id } = req.user;
    const { path: oldPath, originalname } = req.file;

    await jimp.read(oldPath).then((img) => {
      img.resize(250, 250).quality(60).write(oldPath);
    });

    const filename = `${_id}_${originalname}`;
    const newPath = path.join(avatarPath, filename);
    await fs.rename(oldPath, newPath);

    const avatarURL = path.join("avatars", filename);
    await User.findByIdAndUpdate(_id, { avatarURL });

    res.json({
      avatarURL,
    });
  } catch (error) {
    next(error);
  }
};

export default {
  register,
  verify,
  resendVerify,
  login,
  getCurrent,
  logout,
  subscription,
  updateAvatar,
};
