import { ErrorCode } from "../../common/enums/error-code.enum";
import { VerificationEnum } from "../../common/enums/verification-code.enum";
import { LoginDto, RegisterDto } from "../../common/interface/auth.interface";
import { BadRequestException } from "../../common/utils/catch-errors";
import { fortyFiveMinutesFromNow } from "../../common/utils/date-time";
import { config } from "../../config/app.config";
import sessionModal from "../../database/models/session.model";
import userModal from "../../database/models/user.modal";
import VerificationCodeModel from "../../database/models/verification.model";
import jwt from "jsonwebtoken";

export class AuthService {
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

    const verificationCode = await VerificationCodeModel.create({
      userId,
      type: VerificationEnum.EMAIL_VERIFICATION,
      expiresAt: fortyFiveMinutesFromNow(),
    });

    return { user: newUser };
  }

  public async login(loginData: LoginDto) {
    const { email, password, userAgent } = loginData;
    const user = await userModal.findOne({ email });

    if (!user) {
      throw new BadRequestException(
        "Invalid email or password provided",
        ErrorCode.AUTH_USER_NOT_FOUND
      );
    }

    // Compare password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      throw new BadRequestException(
        "Invalid email or password provided",
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
    const refreshToken = jwt.sign(
        {
          sessionId: session._id,
        },
        config.JWT.REFRESH_SECRET,
        {
          audience: ["user"],
          expiresIn: config.JWT.REFRESH_EXPIRES_IN,
        }
      );

    return {user, accessToken ,refreshToken,mfaRequired:false};
  }
}
