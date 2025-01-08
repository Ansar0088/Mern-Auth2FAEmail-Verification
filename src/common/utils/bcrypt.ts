import bcrypt from "bcrypt"


export const hashValue = async(value:string,saltRounds:number=10) :Promise<string> => {
   return await bcrypt.hash(value,saltRounds);
}


export const comapareValue=async (value:string,hashValue:string): Promise<boolean>=>{
   return await bcrypt.compare(value, hashValue);
}