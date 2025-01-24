export interface SigninUserInterface{
    email: string;
    password: string;
}

export interface User{
    email: string;
    password: string;
    name: string;
    role: string;
}

export interface URequest extends Request{
    user?: SigninUserInterface;
}