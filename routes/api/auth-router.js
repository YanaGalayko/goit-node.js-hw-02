import express from "express";
import authController from "../../controllers/auth-controller.js";
import isEmptyBody from "../../utils/middlewares/isEmptyBody.js";
import {
  userRegisterSchema,
  userLoginSchema,
  userSubscriptionSchema,
  userEmailSchema,
} from "../../utils/validation/authValidationSchemas.js";
import { validateBody } from "../../utils/decorators/validateBody.js";
import authenticate from "../../utils/middlewares/authenticate.js";
import upload from "../../utils/middlewares/upload.js";

const authRouter = express.Router();

authRouter.post(
  "/register",
  isEmptyBody,
  validateBody(userRegisterSchema),
  authController.register
);

authRouter.get("/verify/:verificationToken", authController.verify);

authRouter.post(
  "/verify",
  isEmptyBody,
  validateBody(userEmailSchema),
  authController.resendVerify
);

authRouter.post(
  "/login",
  isEmptyBody,
  validateBody(userLoginSchema),
  authController.login
);

authRouter.get("/current", authenticate, authController.getCurrent);

authRouter.post("/logout", authenticate, authController.logout);

authRouter.patch(
  "/subscription",
  authenticate,
  isEmptyBody,
  validateBody(userSubscriptionSchema),
  authController.subscription
);

authRouter.patch(
  "/avatars",
  upload.single("avatar"),
  authenticate,
  authController.updateAvatar
);

export default authRouter;
