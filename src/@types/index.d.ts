import { UserDocument } from "../database/models/user.modal";
import { Response } from "express";

declare global {
  namespace Express {
    interface user extends UserDocument {}
    interface Request{
        sessionId?:string;
    }
  }
}
