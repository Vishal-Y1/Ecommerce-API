const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) =>{
    const authHeader = req.headers.token
    if(authHeader){
        const token = authHeader.split(" ")[1];
        jwt.verify(token, process.env.JWT, (error, user)=>{
            if(error) res.status(403).json("token is not valid");
            req.user = user
            next();
        })
    }else{
        return res.status(401).json('You are not authenticated')
    }
};

const verifyTokenAndAuthorization = (req, res, next)=>{
    verifyToken(req, res,()=>{
        if(req.user.id === req.params.id || req.user.isAdmin){
            next();
        }else{
            res.status(403).json('You are not allowed to continue')
        }
    })
};

const verifyTokenAndAdmin = (req, res, next)=>{
    verifyToken(req, res,()=>{
        if(req.user.isAdmin){
            next();
        }else{
            res.status(403).json('You are not allowed to continue')
        }
    })
};

module.exports = {verifyToken, verifyTokenAndAuthorization,verifyTokenAndAdmin};