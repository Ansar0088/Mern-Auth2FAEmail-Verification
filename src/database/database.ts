import mongoose from "mongoose";
import { config } from "../config/app.config";


const connectDatabase= async()=>{
    try{
        await mongoose.connect(config.MONGO_URI)
        console.log("DB is Connected successfully")
    }catch (error){
        console.log("DB is Not Connected",error)
        process.exit(1);

    }
}

export default connectDatabase;