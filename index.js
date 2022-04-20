const express = require("express")
const app = express()
const mongoose = require("mongoose")
const User = require("./model/User")
const bodyParser = require("body-parser")
const jsonParser = bodyParser.json()
const bcrpyt = require("bcrypt")
const jwt = require("jsonwebtoken")
const Token = require("./model/Token")



jwtkey = "jwt"

mongoose.connect("mongodb+srv://maaz:azamhamed0@cluster0.biaxw.mongodb.net/jwtTest?retryWrites=true&w=majority",{
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(()=>{
    console.log("connected");
}).catch((err)=>{
    console.log(err)
})

const checkToken = async(req,res,next) => {
    const bearerHeader = req.headers["authorization"]
    console.log(bearerHeader)
    if(typeof bearerHeader !== "undefined"){
        jwt.verify(bearerHeader,jwtkey, (err, auth)=>{
            if(err){
                res.json(err)
                res.end()
            } else next()
        })
    } else{
        res.end("Token not found")
    }
}

const makePassword = async (password) => {
    let SALT_ROUNDS = 10
    try{
        let hashedPass = await bcrpyt.hash(password,SALT_ROUNDS)
        return hashedPass
    } catch (e) {
        console.log(e)
    }
}

const matchPassword = async (password,finalPass) => {
    return await bcrpyt.compare(password,finalPass)
}

app.post("/register",jsonParser,async(req,res)=>{
    let {password , name , email} = req.body
    finalPass = await makePassword(password)
    const data = new User({
        name,
        email,
        password: finalPass
    })
    result = await data.save()
    jwt.sign({result}, jwtkey, { expiresIn: "10s"},(err,token)=>{
        res.status(201).json({token})
    })
    
    
})

app.post("/login",jsonParser,async(req,res)=>{
    let {email,password}= req.body
    let reqUser = await User.findOne({email})
    if(reqUser){
        let isVerified = await matchPassword(password,reqUser.password)
        if(isVerified){

            let token = jwt.sign({reqUser},jwtkey,{expiresIn:"30s"})
            let newToken = new Token({
                token,
                userId: reqUser._id 
            })
            await newToken.save()
            console.log(token)
            res.json({token})

            
            
        }
        else{
            res.end("no user")
        }
    }
})

app.get("/all-users",checkToken,async(req,res)=>{
    let result = await User.find()
    if(result){
        res.status(200).json(result)
    } else{
        res.end("not authenticated")
    }
})






app.listen(4000,()=>console.log("localhost:4000"))