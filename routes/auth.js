const express = require('express');
const router = express.Router();
const User = require('../models/User.model');
const bcrypt = require('bcryptjs');

router.get('/signup', (req, res) => {
    res.render('auth/signup')
})

router.post('/signup', async (req, res) => {
    const {
        username,
        email,
        password
    } = req.body;

    //check if empty
    if (username === '' || password === '') {
        res.render('auth/signup', {
            errorMessage: 'Indicate username and password'
        })
        return
    }

    //check for pw strength - with regular expression (language that detect patterns in a string)
    const passwordRegex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/
    if (!passwordRegex.test(password)) {
        res.render('auth/signup', {
            errorMessage: 'Password is too weak: It must have at least 6 characters, one number, one lowercase, and one uppercase!'
        })
        return;
    }

    // check if user already exists
    let user = await User.findOne({
        username: username
    });
    if (user !== null) {
        res.render('auth/signup', {
            errorMessage: 'Username already exists'
        })
        return
    }

    //check if email already exists
    user = await User.findOne({
        email: email
    });
    if (user !== null) {
        res.render('auth/signup', {
            errorMessage: 'Email already exists'
        })
        return;
    }

    //create user with encrypted PW
    const saltRounds = 10;
    const salt = bcrypt.genSaltSync(saltRounds);
    const hashedPassword = bcrypt.hashSync(password, salt);
    try {
        await User.create({
            username,
            email,
            password: hashedPassword
        });
        res.redirect('/');
    } catch (e) {
        res.render('auth/signup', {
            errorMessage: 'Error occurred'
        });
        return; {}
    }

});


module.exports = router;