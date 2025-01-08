import cookieParser from "cookie-parser";
import "dotenv/config";
import cors from "cors";
import express from "express";
import { config } from "./config/app.config";
import connectDatabase from "./database/database";
import { errorHandler } from "./middlewares/errorHandler";
import { HTTPSTATUS } from "./config/http.config";
import { asyncHandler } from "./middlewares/asyncHandler";
import authRouter from "./modules/auth/auth.routes";

const app = express();
const BASE_PATH=config.BASE_PATH;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cors({ 
    credentials: true,
    origin: config.APP_ORIGIN,
}));

app.use(cookieParser());

app.get('/', asyncHandler(async (req, res) => {
    res.status(HTTPSTATUS.OK).json({
        message: "hello subscribers!!"
    });
}));

app.use(`${BASE_PATH}/auth`,authRouter)
app.use(errorHandler);

app.listen(config.PORT, async () => {
    console.log(`Server listening on port ${config.PORT} in ${config.NODE_ENV}`);
    await connectDatabase();
});
function async(req: any, res: any): (req: express.Request, res: express.Response, next: express.NextFunction) => Promise<any> {
    throw new Error("Function not implemented.");
}

