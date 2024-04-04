const router = require("express").Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


//REGISTER
router.post("/register", async (req, res) => {
    try {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt);
        const newUser = new User({...req.body, password:hash});
        const savedUser = await newUser.save();
        const {password, ...others} = savedUser._doc
        res.status(201).json(others)
    } catch (error) {
        res.status(500).json(error)
    }
});

//LOGIN
router.post("/login",async (req, res) => {
    try {
        const user = await User.findOne({username: req.body.username});
        if(!user) return res.status(404).json("no user found");

        const isCorrect = await bcrypt.compare(req.body.password, user.password);
        if(!isCorrect) return res.status(404).json("wrong credentials");

        const token = jwt.sign({id:user._id, isAdmin: user.isAdmin,}, process.env.JWT,{expiresIn:"3d"});
        const {password, ...others} = user._doc;

        // res.cookie("access_token", token, {
        //     httpOnly: true,
        // }).status(200).json({...others, token});

        res.status(200).json({...others, token});
    } catch (error) {
        res.status(500).json(error)
    }
})

module.exports = router;