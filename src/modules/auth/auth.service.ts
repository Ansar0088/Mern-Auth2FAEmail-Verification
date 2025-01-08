import { RegisterDto } from "../../common/interface/auth.interface";
import userModal from "../../database/models/user.modal";

export class AuthService{
   public async register(registerData:RegisterDto){
    const {name,email,password,userAgent}=registerData
    const existingUser=await userModal
   }
}