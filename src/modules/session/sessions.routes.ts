import { Router } from "express";
import { SessionController } from "./session.controller";

const sessionRoutes = Router();


sessionRoutes.get("/all",SessionController.getAllSessions);

export default sessionRoutes;
