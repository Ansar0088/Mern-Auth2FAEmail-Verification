import { asyncHandler } from "../../middlewares/asyncHandler";
import { SessionService } from "./session.service";
import { Request, Response } from "express";
export class SessionController {
    private sessionService: SessionService;

  constructor(sessionService: SessionService) {
    this.sessionService = sessionService;
  }

  public getAllSession = asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const sessionId = req.sessionId;

    const sessions = await this.sessionService.getAllSessions(userId);

    }
  );
}1
