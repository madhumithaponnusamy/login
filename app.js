const express = require('express');
const app = express();
const PORT = 3008;
const path = require('path');



const rfs = require('rotating-file-stream');
const pino = require('pino');
const pinoHttp = require('pino-http');
const session = require('express-session');

const MySQLStore = require("express-mysql-session")(session);

const createDBConnection = require('../db/db')
const crypto = require("crypto");
const { saveLog } = require("./logger/logger");

let db = ""

const { checkAuthentication, AlreadyLoggedIn } = require('./middleware/middleware');


const generator = (time, testapp) => {
    const d = time || new Date();
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');

    return `${year}-${month}-${day}.log`;
};

const stream = rfs.createStream(generator, {
    interval: '1d',
    path: path.join(__dirname, 'logs'),
});

const logger = pino(
    { transport: { target: "pino-pretty", options: { colorize: true } } },
    stream
);

app.use(pinoHttp({ logger }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const sessionStore = new MySQLStore({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'ecommercedetails',
    checkExpirationInterval: 900000, // 15 mins
    expiration: 1000 * 60 * 60 * 2
});



app.use(session({
    name: 'sid',
    secret: process.env.SESSION_SECRET || 'change_this_secret',
    store: sessionStore,
    resave: false,

    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        maxAge: 1000 * 60 * 60 * 2 // 2 hours
    }
}));

app.use((req, res, next) => {
    req.reqId = crypto.randomBytes(8).toString("hex");
    next();
});

app.use((req, res, next) => {
    console.log("Incoming:", req.method, req.url);
    next();
});

app.set("view engine", "ejs");
app.set("views", [
    path.join(__dirname, "views"),
]);


async function startService() {
    db = await createDBConnection()

    app.use((req, res, next) => {
        req.db = db;
        next();
    });

    app.use((req, res, next) => {
        const start = Date.now();
        res.on("finish", () => {
            saveLog(req.db, {
                reqId: req.reqId,
                level: "request",
                msg: "HTTP Request",
                meta: {
                    method: req.method,
                    url: req.url,
                    status: res.statusCode,
                    responseTime: Date.now() - start + "ms"
                }
            });
        });
        next();
    });

    const loginformController = require("./controller/loginform.controller");
    loginformController.setupRoutes(app)


    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });

}


startService()