const bcrypt = require('bcryptjs')
const db = require('../infrastructure/database/connection');

exports.registerUser = (req,res) =>{
    const {nama,email,password} = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    const sql = 'insert into users (nama, email,password) values(?,?,?)'
    db.query(sql, [nama,email, hashedPassword], (err, result) => {
        if(err) {
            return res.status(500).json({message: err.message})
        }
        res.redirect('/')
    })
}

exports.renderRegister = (req, res) => {
    res.render('register',{
        title: 'Register',
        layout: 'layouts/main-layout',
        showNavbar: false,
        showFooter: false
        
    });
};

exports.loginUser = (req, res) => {
    const {email, password} = req.body;
    const sql ='select * from users where email =?'
    db.query(sql, [email], (err, result) => {
        if(err) 
            return res.status(500).json({message: err.message})
        if(result.length === 0) 
            return res.status(404).json({message: 'User not found'})
        const match = bcrypt.compareSync(password, result[0].password)
        if(!match) 
            return res.status(401).json({message: 'Invalid credentials'})
        
        req.session.nama = result[0].nama
        req.session.userId = result[0].id;
        res.redirect('/')
    })
}

exports.renderLogin = (req, res) => {
    res.render('login',{
        title: 'Login',
        layout: 'layouts/main-layout',
        showNavbar: false,
        showFooter: false
        
    });
}

exports.logoutUser = (req, res) => {
    req.session.destroy((err) => {
        if(err) 
            return res.status(500).json({message: err.message})
        res.clearCookie('connect.sid');
        res.redirect('/login')
    })
}