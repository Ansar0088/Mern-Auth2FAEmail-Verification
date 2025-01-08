import zod from "zod";

export const emilSchema = zod.string().trim().email().min(1).max(222);
export const passwordSchema = zod.string().trim().min(6).max(222);

export const registerSchema = zod.object({
  name: zod.string().trim().min(1).max(222),
  email: emilSchema,
  password:passwordSchema,
  confirmPassword:passwordSchema,
  userAgent:zod.string().optional(),
}).refine((val)=>val.password===val.confirmPassword,{
    message:"password does not match",
    path:["confirmPassword"],
})

export const loginSchema=zod.object({
    email:emilSchema,
    password:passwordSchema,

})
