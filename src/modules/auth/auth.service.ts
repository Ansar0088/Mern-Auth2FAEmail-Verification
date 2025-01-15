import { ErrorCode } from "../../common/enums/error-code.enum";
import { VerificationEnum } from "../../common/enums/verification-code.enum";
import {
  LoginDto,
  RegisterDto,
  resetPasswordDto,
} from "../../common/interface/auth.interface";
import {
  BadRequestException,
  HttpException,
  InternalServerException,
  NotFoundException,
  UnauthorizedException,
} from "../../common/utils/catch-errors";
import {
  anHourFromNow,
  calculateExpirationDate,
  fortyFiveMinutesFromNow,
  ONE_DAY_IN_MS,
  threeMinutesAgo,
} from "../../common/utils/date-time";
import { config } from "../../config/app.config";
import sessionModal from "../../database/models/session.model";
import userModal from "../../database/models/user.modal";
import VerificationCodeModel from "../../database/models/verification.model";
import jwt from "jsonwebtoken";
import {
  refreshTokenSignOptions,
  RefreshTPayload,
  signJwtToken,
  verifyJwtToken,
} from "../../common/utils/jwt";
import { sendEmail } from "../../mailers/mailer";
import {
  passwordResetTemplate,
  verifyEmailTemplate,
} from "../../mailers/templates/template";
import { HTTPSTATUS } from "../../config/http.config";
import { hashValue } from "../../common/utils/bcrypt";

export class AuthService {
  // REGISTER API MEAN CREATE LOGIN USER API OR CHECK  EMAIL EXIST THIS IS NOT CREATED-------

  public async register(registerData: RegisterDto) {
    const { name, email, password } = registerData;
    const existingUser = await userModal.exists({ email });

    if (existingUser) {
      throw new BadRequestException(
        "User already exists with this email",
        ErrorCode.AUTH_EMAIL_ALREADY_EXISTS
      );
    }

    const newUser = await userModal.create({ name, email, password });
    const userId = newUser._id;

    const verification = await VerificationCodeModel.create({
      userId,
      type: VerificationEnum.EMAIL_VERIFICATION,
      expiresAt: fortyFiveMinutesFromNow(),
    });

    const verificationUrl = `${config.APP_ORIGIN}/confirm-account?code=${verification.code}`;
    await sendEmail({
      to: newUser.email,
      ...verifyEmailTemplate(verificationUrl),
    });

    return { user: newUser };
  }

  // Login API WITH COMPATRE PASSWORD CHECK SESSION REFRESH TOKEN & ACCESS TOKEN-----------

  public async login(loginData: LoginDto) {
    const { email, password, userAgent } = loginData;
    const user = await userModal.findOne({ email });

    if (!user) {
      throw new BadRequestException(
        "Invalid  hai Ansar email or password provided ",
        ErrorCode.AUTH_USER_NOT_FOUND
      );
    }

    // Compare password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      throw new BadRequestException(
        "Ansar Invalid email or password provided",
        ErrorCode.AUTH_USER_NOT_FOUND
      );
    }

    // Check session
    const session = await sessionModal.create({
      userId: user._id,
      userAgent,
    });

    // Access token
    const accessToken = jwt.sign(
      {
        userId: user._id,
        sessionId: session._id,
      },
      config.JWT.SECRET,
      {
        audience: ["user"],
        expiresIn: config.JWT.EXPIRES_IN,
      }
    );

    // Refresh Token

    const refreshToken = signJwtToken(
      {
        sessionId: session._id,
      },
      refreshTokenSignOptions
    );
    return { user, accessToken, refreshToken, mfaRequired: false };
  }

  // REFRESH TOKKEN API------

  public async refreshToken(refreshToken: string) {
    const { payload } = verifyJwtToken<RefreshTPayload>(refreshToken, {
      secret: refreshTokenSignOptions.secret,
    });

    if (!payload) {
      throw new UnauthorizedException("Invalid refresh token");
    }

    const session = await sessionModal.findById(payload.sessionId);
    const now = Date.now();

    if (!session) {
      throw new UnauthorizedException("Session does not exist");
    }

    if (session.expiredAt.getTime() <= now) {
      throw new UnauthorizedException("Session expired");
    }

    const sessionRequireRefresh =
      session.expiredAt.getTime() - now <= ONE_DAY_IN_MS;

    if (sessionRequireRefresh) {
      session.expiredAt = calculateExpirationDate(
        config.JWT.REFRESH_EXPIRES_IN
      );
      await session.save();
    }

    const newRefreshToken = sessionRequireRefresh
      ? signJwtToken(
          {
            sessionId: session._id,
          },
          refreshTokenSignOptions
        )
      : undefined;

    const accessToken = signJwtToken({
      userId: session.userId,
      sessionId: session._id,
    });

    return {
      accessToken,
      newRefreshToken,
    };
  }

  // verifyEmail API------
  public async verifyEmail(code: string) {
    const validCode = await VerificationCodeModel.findOne({
      code: code,
      type: VerificationEnum.EMAIL_VERIFICATION,
      expiresAt: { $gt: new Date() },
    });
    if (!validCode) {
      throw new BadRequestException("Invalid or expired verification code");
    }

    const updatedUser = await userModal.findByIdAndUpdate(
      validCode.userId,
      { isEmailVerified: true },
      { new: true }
    );
    if (!updatedUser) {
      throw new BadRequestException(
        "Unable to verify email address",
        ErrorCode.VALIDATION_ERROR
      );
    }
    await validCode.deleteOne();
    return {
      user: updatedUser,
    };
  }

  // forgotPassword API------

  public async forgotPassword(email: string) {
    const user = await userModal.findOne({
      email: email,
    });
    if (!user) {
      throw new NotFoundException("User not found");
    }
    //check mail rate limit is 2 emails per 3 or 10 min
    const timeAgo = threeMinutesAgo();
    const maxAttempts = 2;

    const count = await VerificationCodeModel.countDocuments({
      userId: user._id,
      type: VerificationEnum.PASSWORD_RESET,
      createdAt: { $gt: timeAgo },
    });
    if (count >= maxAttempts) {
      throw new HttpException(
        "Too many requests try again later",
        HTTPSTATUS.TOO_MANY_REQUESTS,
        ErrorCode.AUTH_TOO_MANY_ATTEMPTS
      );
    }
    const expiresAt = anHourFromNow();
    const validCode = await VerificationCodeModel.create({
      userId: user._id,
      type: VerificationEnum.PASSWORD_RESET,
      expiresAt,
    });
    const resetLink = `${config.APP_ORIGIN}/reset-password?code=${
      validCode.code
    }&exp=${expiresAt.getTime()}`;

    const { data, error } = await sendEmail({
      to: user.email,
      ...passwordResetTemplate(resetLink),
    });
    if (!data?.id) {
      throw new InternalServerException(`${error?.name} ${error?.message}`);
    }

    return {
      url: resetLink,
      emailId: data.id,
    };
  }

  // resetPassword API------

  public async resetPassword({ password, verificationCode }: resetPasswordDto) {
    const validCode = await VerificationCodeModel.findOne({
      code: verificationCode,
      type: VerificationEnum.PASSWORD_RESET,
      expiresAt: { $gt: new Date() },
    });
    if (!validCode) {
      throw new BadRequestException("Invalid or expired verification code");
    }

    const hashedPassword = await hashValue(password);

    const updatedUser = await userModal.findByIdAndUpdate(validCode.userId, {password: hashedPassword,});

    if (!updatedUser) {
      throw new BadRequestException("Failed to reset password!");
    }

    await validCode.deleteOne();

    await sessionModal.deleteMany({
      userId: updatedUser._id,
    });

    return {
      user: updatedUser,
    };
  }

  // logout API------

  public async logout (sessionId: string) {
    return await sessionModal.findByIdAndDelete(sessionId);
  }
}
