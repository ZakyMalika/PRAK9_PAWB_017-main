const express = require('express');
const bodyParser = require('body-parser');
const user = require('./auth');
const todo = require('./todo');
const session = require('express-session');
const expressejslayouts = require('express-ejs-layouts');
const path = require('path');

const app = express();
app.set('view engine','ejs');


app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false }
}));

console.log('D:\SEMESTER 3\PAW\ini\PRAK9_PAWB_017-main\src\app\public')
app.use(expressejslayouts);
app.set('views', path.join(__dirname, '../views'));
app.use(express.static(path.join('D:\SEMESTER 3\PAW\ini\PRAK9_PAWB_017-main\src\app\public')));
app.set('layout','layouts/main-layout')

app.use(bodyParser.urlencoded({ extended: false })); // for parsing application/x-www-form-urlencoded
app.use(bodyParser.json());
app.use('/',user);
app.use('/todos',todo);

module.exports = app;




