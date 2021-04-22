const express = require('express');
const router = express.Router();

/* GET home page */
function requireLogin(req, res, next) {
    if (req.session.currentUser) {
        next();
    } else {
        res.redirect('/login');
    }
}

router.get('/', (req, res, next) => {
    res.render('index', {
        user: req.session.currentUser
    });
});

router.get('/private', requireLogin, (req, res) => {
    res.render('private');
});

router.get('/main', requireLogin, (req, res) => {
    res.render('main');
});

module.exports = router;