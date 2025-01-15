import userModal from "../../database/models/user.modal";

export class UserService{
    public async findUserById(userId:string){
        const user= await userModal.findById(userId,{
            password:false,
        });
        return user|| null
    }
}