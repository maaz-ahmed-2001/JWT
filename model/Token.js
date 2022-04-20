const mongoose = require("mongoose")
const tokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true
    },
    userId: {
        type : String
    },
    exp : {
        type: Number
    }
})

module.exports = mongoose.model("token",tokenSchema)