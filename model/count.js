const mongoose = require('mongoose')
mongoose.set('useFindAndModify', false)
mongoose.connect('mongodb://localhost:27017/accountapicount', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})

const Schema = mongoose.Schema
const apicountSchema = new Schema({
    count0: Number,
    count1: Number,
    count2: Number,
    count3: Number,
    count4: Number,
    count5: Number,
    count6: Number,
    count7: Number,
    count8: Number,
    count: Number,

})

const Apicount = mongoose.model('Apicount', apicountSchema, 'apicount')
module.exports = Apicount