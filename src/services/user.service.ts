import admin, { db } from "../config/db.config";
import { SigninUserInterface, User } from "../interfaces/user.signin.interface";
import bcrypt from 'bcrypt';
import axios from 'axios';

const Admin = admin.auth()
const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY

export class UserService {

    async create(user: User): Promise<User | any> {
        const email = user.email;
        const password = user.password;
        try {
            const existingUser = await Admin.getUserByEmail(email).catch(() => null);
            if (existingUser){
                throw new Error('User already exists');
            }
            const hashPassword = await bcrypt.hash(password, 10);
            const newUser = await Admin.createUser({
                ...user,
                password: hashPassword
            })
            await db.collection('Users').doc(newUser.uid).set({
                uid: newUser.uid,
                ...user
            })

            return newUser
            
        } catch (error) {
            throw error
        }
    };

    async signIn(user: SigninUserInterface): Promise<string> {
        const email = user.email;
        const password = user.password;
        try {
            const existingUser = await Admin.getUserByEmail(email).catch(() => null);
            if (!existingUser){
                throw new Error('User does not exist');
            }

            const signInUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`;

            const {data} = await axios.post(signInUrl, {email, password, returnSecureToken: true});

            return data.idToken;
        } catch (error) {
            throw error
        }
    }
}