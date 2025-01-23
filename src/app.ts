import express from 'express';
import dotenv from 'dotenv';
dotenv.config();
import cors from 'cors';
import './config/db.config';
import { errorHandler } from './middlewares/errorHandler';


const app = express();


app.use(cors());
const port = process.env.PORT || 5000;
app.listen(port, () => { 
    console.log('Server is running on port 3000');
})
app.use(errorHandler);