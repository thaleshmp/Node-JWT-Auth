const
    config = require('./config'),
    fs = require('fs'),
    express = require('express'),
    api = express(),
    cors = require('cors'),
    jwt = require('jsonwebtoken')

api.use(cors())
api.use(express.json())
api.use(express.urlencoded({
    extended: true
}));

const userDB = JSON.parse(fs.readFileSync('./simpleDB.json', 'utf8'));

function authUser(username, password) {
    var user = userDB.filter((user) => (user.username == username && user.password == password))
    if(user.length > 0){
        return user[0];
    }
    return null;
}

function isAuthorized(req, res, next){
    var token = req.headers['x-access-token'];
    if(!token) return res.status(401).send({auth: false, message: 'missing credentials'});
    jwt.verify(token, config.jwtServerTokenHash, (err, decoded) => {
        if(err) return res.status(401).send({auth: false, message: 'provided token is invalid or expired'});
        req.userId = decoded.id;
        next();
    });
}


api.get('/user', isAuthorized, (req, res, next) => {
    return res.status(200).send({userId: req.userId});
})

api.post('/token', (req, res, next) => {
    //AUTH
    var credentials = req.body;
    if(credentials['username'] && credentials['password']){
        var user = authUser(credentials['username'], credentials['password']);
        if(user){
            var token = jwt.sign({ id: user.id }, config.jwtServerTokenHash, {
                expiresIn: 300 // expires in 5min
            });
            res.status(200).send({
                auth: true,
                token: token
            });
        }
        else{
            res.status(401).send();
        }
    }
    else {
        res.status(400).send();
    }
})

api.listen(config.port, () => {
    console.log('listening to port ' + config.port)
});