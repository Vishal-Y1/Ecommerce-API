const router = require("express").Router();
const { verifyToken, verifyTokenAndAuthorization, verifyTokenAndAdmin } = require("./verifyToken");
const User = require("../models/User");
const bcrypt = require('bcrypt');


//UPDATE
router.put("/:id", verifyTokenAndAuthorization, async (req, res) => {
    try {
        const salt = await bcrypt.genSaltSync(10);
        const hash = await bcrypt.hashSync(req.body.password, salt);
        
        const updates = await User.findByIdAndUpdate(
            req.params.id,
            {$set: {...req.body, password: hash}},
            {new: true}
            )

        res.status(200).json(updates);

    } catch (error) {
        res.status(500).json(error)
    }
});

//DELETE
router.delete("/:id", verifyTokenAndAuthorization, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id)
        res.status(200).json("User deleted successfully")
    } catch (error) {
        res.status(500).json(error)
    }
});

//GET A USER
router.get("/find/:id", verifyTokenAndAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
        const { password, ...others } = user._doc;
        res.status(200).json({ others });
    } catch (error) {
        res.status(500).json(error)
    }
});

//GET ALL USERS
router.get("/", verifyTokenAndAdmin, async (req, res) => {
    const query = req.query.new
    try {
        const users = query ? await User.find().sort({ _id: -1 }).limit(5) : await User.find();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json(error)
    }
});

//GET USER STATS

router.get("/stats", verifyTokenAndAdmin, async (req, res) => {
    const date = new Date();
    const lastYear = new Date(date.setFullYear(date.getFullYear() - 1));

    try {
        const data = await User.aggregate([
            { $match: { createdAt: { $gte: lastYear } } },
            {
                $project: {
                    month: { $month: "$createdAt" },
                },
            },
            {
                $group: {
                    _id: "$month",
                    total: { $sum: 1 },
                },
            },
        ]);
        res.status(200).json(data);
    } catch (error) {
        res.status(500).json(error)
    }
});



module.exports = router;