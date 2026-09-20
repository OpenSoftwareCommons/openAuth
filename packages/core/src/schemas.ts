import { z } from "zod";

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(254)
  .email("invalid email");

export const passwordSchema = z
  .string()
  .min(8, "password must have at least 8 characters")
  .max(128, "password must have at most 128 characters");

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  roles: z.array(z.string().min(1).max(64)).max(32).optional(),
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(128),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
