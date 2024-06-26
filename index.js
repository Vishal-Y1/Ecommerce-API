const express = require("express");
const mongoose = require('mongoose');
const dotenv = require("dotenv");
const app = express();
const userRoute = require("./routes/user")
const authRoute = require("./routes/auth");
const productRoute = require("./routes/product");
const cartRoute = require("./routes/cart");
const orderRoute = require("./routes/order");

dotenv.config();

mongoose.connect(process.env.MONGO_URL)
.then(() => console.log("db connected"))
.catch((err) =>{
    console.log("db error "+err)
});

app.use(express.json());
app.use("/api/auth", authRoute);
app.use("/api/users", userRoute);
app.use("/api/products", productRoute);
app.use("/api/carts", cartRoute);
app.use("/api/orders", orderRoute);

app.listen(process.env.PORT || 5000, ()=> {
    console.log("server listening to 3344");
});
