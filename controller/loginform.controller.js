const query = require("./loginform.query");
const { checkAuth, AlreadyLoggedIn } = require("../middleware/middleware")


function loginForm(req, res) {
    if (req.session.userId) {
        return res.redirect("/api/dashboard");
    }

    res.render("userlogin", {
        title: "Login Page",
        error: null
    });
}

async function handleLogin(req, res) {
    const { username, password } = req.body;

    if (!password || !username) {
        return res.status(400).render("userlogin", {
            title: "userlogin",
            error: "Username and password are required"
        });
    }


    try {
        const querySQL = query.SELECTUserByUserName;
        const [rows] = await req.db.execute(querySQL,[username,password]);

        if (rows.length === 0) {
            return res.status(401).render("userlogin", {
                title: "Login",
                error: "Invalid username or password"
            });
        }

        const user = rows[0];

        if (user.password !== password) {
            return res.status(401).render("userlogin", {
                title: "Login",
                error: "Invalid username or password"
            });
        }

        req.session.userId = user.userId;
        req.session.userName = user.userName;

        req.session.save((err) => {
            if (err) {
                console.error("Session save error:", err);
                return res.status(500).send("Session save error");
            }
            res.redirect("/api/dashboard");
        });

    } catch (err) {

        console.error("Login error:", err);
        res.status(500).render("userlogin", {
            title: "Login",
            error: "Server error. Please try again."
        });
    }
}

function handleLogout(req, res) {
    req.session.destroy((err) => {
        if (err) {
            console.error("Session destroy error:", err);
            return res.status(500).send("Logout error");
        }
        res.redirect("/api/loginpage");
    })
}

function dashboard(req, res) {
    if (!req.session.userId) {
        return res.redirect("/api/loginpage");
    }

    res.render("dashboardform", {
        title: "Dashboard",
        user: {
            id: req.session.userId,
            name: req.session.userName,
        }
    });
}



function setupRoutes(app) {

    app.get("/api/loginpage", AlreadyLoggedIn, loginForm);

    app.post("/api/login", handleLogin);

    app.get("/api/logout", checkAuth, handleLogout);

    app.get("/api/dashboard", checkAuth, dashboard)



}

module.exports = {
    setupRoutes
};