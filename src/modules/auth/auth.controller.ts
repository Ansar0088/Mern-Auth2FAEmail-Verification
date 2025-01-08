import { registerSchema } from "../../common/validators/auth.validators";
import { HTTPSTATUS } from "../../config/http.config";
import { asyncHandler } from "../../middlewares/asyncHandler";
import { AuthService } from "./auth.service";
import { Request, Response } from "express";

export class AuthController {
  private authService: AuthService;
  constructor(authService: AuthService) {
    this.authService = authService;
  }

  public register = asyncHandler(
    async (req: Request, res: Response): Promise<any> => {
        const userAgent=req.headers["user-agent"];
         const body=registerSchema.parse({
            ...req.body,
            userAgent,
         });
         this.authService.register(body)
      return res.status(HTTPSTATUS.CREATED).json({          
        message: "User register successfully",
        name: "ansar",
      });
    }
  );
}
