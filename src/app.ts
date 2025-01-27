import express from 'express';
import dotenv from 'dotenv';
dotenv.config();
import cors from 'cors';
import './config/db.config';
import { errorHandler } from './middlewares/errorHandler';
import userRoute from './routers/user.router';
import bodyParser from 'body-parser';


const app = express();


app.use(cors());
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use('/api/v1/users', userRoute);

const port = process.env.PORT || 5000;
app.listen(port, () => { 
    console.log('Server is running on port 3000');
})
app.use(errorHandler);