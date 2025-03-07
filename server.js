require('dotenv').config()
const express=require('express')
const mongoose=require('mongoose')
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const cors=require('cors')
const cookieParser=require('cookie-parser')

const PORT=process.env.PORT || 3000;
const SECRET=process.env.JWT_SECRET
const DB_URL=process.env.DB_URL

mongoose.connect(DB_URL)
        .then(()=>console.log("Databse connected"))
        .catch(er=>console.log(er))

const userSchema=new mongoose.Schema({
    username:{type:String, required:true},
    password:{type:String, required:true}
})

const userModel=mongoose.model("user", userSchema);

const app=express();
app.use(express.json());
app.use(cors());
app.use(cookieParser());

app.get('/',(req,res)=>{
    return res.status(200).send("API IS WORKING");
})

app.post('/register', async(req,res)=>{
    try{
        const {username, password}= req.body;
        if(!username || !password){
            return res.status(400).send({message:"Provide all credentials"})
        }
        const user=await userModel.findOne({username});
        if(user){
            return res.status(400).send({message:"user already exists."})
        }
        
        hashedPassword= await bcrypt.hash(password, 10);
        const newUser= await userModel.create({username,password:hashedPassword});
        
        return res.status(200).send({message:"User registered successfully.", newUser})
    }catch(er){
        return res.status(500).send({message:"internal server error", er:er.message})
    }

})

app.post('/login', async(req,res)=>{
    try{
        const {username, password}= req.body;
        const user=await userModel.findOne({username});
        if(!user){
            return res.status(404).send({message:"User doesn't exist"})
        }

        const isMatch=await bcrypt.compare(password, user.password);
        if(!isMatch){
            return res.status("Invalid password");
        }

        const token=jwt.sign({username, password}, SECRET, {expiresIn:"1h"});
        res.cookie("token", token, {httpOnly:true});
        res.status(200).send({message:"Login successful "})

    }catch(er){
        return res.status(500).send({message:"Internal server error.", er:er.message})
    }
})

const middleware=(req,res,next)=>{
    const token=req.cookies.token || req.headers.authorization?.split(" ")[1];
    if(!token){
        return res.status(404).send({messasge:" Token not found "});
    }
    jwt.verify(token, SECRET, (er, user)=>{
        if(er){
            return res.status(404).send({message:"Invalid token"})
        }
        req.user=user;
        next();

    })
}

app.get('/profile', middleware, (req,res)=>{
    const user =req.user.username;
    return res.status(200).send({username:user});
})

app.get('/time', middleware, (req,res)=>{
    return res.status(200).send({time: new Date().toISOString()});
})

app.post('/logout',(req,res)=>{
    res.clearCookie("token");
    res.send({message:"Logged out successfully"});
})

app.listen(PORT, ()=>{
    console.log(`App is running on http://localhost:${PORT}`)
})