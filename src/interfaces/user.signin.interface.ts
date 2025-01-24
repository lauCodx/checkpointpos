import { Request } from "express";

export interface SigninUserInterface{
    email: string;
    password: string;
}

export interface User{
    email: string;
    password: string;
    role?: string;
}

export interface URequest extends Request{
    user?: SigninUserInterface;
}