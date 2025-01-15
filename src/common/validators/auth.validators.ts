import zod from "zod";
export const emilSchema = zod.string().trim().email().min(1).max(222);
export const passwordSchema = zod.string().trim().min(6).max(222);
export const verificationCodeSchema = zod.string().trim().min(1).max(25);
export const registerSchema = zod
  .object({
    name: zod.string().trim().min(1).max(222),
    email: emilSchema,
    password: passwordSchema,
    confirmPassword: passwordSchema,
  })
  .refine((val) => val.password === val.confirmPassword, {
    message: "password does not match",
    path: ["confirmPassword"],
  });

export const loginSchema = zod.object({
  email: emilSchema,
  password: passwordSchema,
  userAgent: zod.string().optional(),
});

export const verificationEmailSchema = zod.object({
  code: verificationCodeSchema,
  password: passwordSchema,
});

export const resetPasswordSchema = zod.object({
  password: passwordSchema,
  verificationCode: verificationCodeSchema,
});
