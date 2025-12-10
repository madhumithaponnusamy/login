const query = require("./loginform.query");
const sendMail = require("../mail/mail")
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
        const [rows] = await req.db.execute(querySQL, [username, password]);

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
        req.session.email = user.email;

        req.session.save((err) => {
            if (err) {
                console.error("Session save error:", err);
                return res.status(500).send("Session save error");
            }
            res.redirect("/api/login/otp");
        });

    } catch (err) {

        console.error("Login error:", err);
        res.status(500).render("userlogin", {
            title: "Login",
            error: "Server error. Please try again."
        });
    }
}

function otpForm(req, res) {
    res.render("otpForm");
}

async function generateOtp(req, res) {
    try {

        if (!req.session.userId) {
            return res.redirect("/api/loginpage");
        }


        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        req.session.otp = otp;
        req.session.otpExpires = expiresAt;

        await sendMail(
            req.session.email,
            "Your OTP Code",
            `Your OTP is ${otp}. It expires in 5 minutes.`
        );

        return res.redirect("/api/otpForm");


    } catch (err) {
        console.error("OTP generation error:", err);
        return res.status(500).send("Failed to generate OTP");
    }
}

async function verifyotp(req, res) {
    try {
        const enteredOtp = req.body.otp;

        // Check if session contains OTP
        if (!req.session.otp || !req.session.otpExpires) {
            return res.send("No OTP found. Please login again.");
        }

        // Check if OTP expired
          if (new Date() > new Date(req.session.otpExpires))  {
            return res.send("OTP expired. Please login again.");
        }

        // Check if OTP matches
        if (enteredOtp !== req.session.otp) {
            return res.send("Invalid OTP. Try again.");
        }

        // OTP correct → redirect to dashboard
        return res.redirect("/api/dashboard");

    } catch (err) {
        console.error("OTP verify error:", err);
        res.status(500).send("Server error during OTP verification");
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

    app.get("/api/login/otp", checkAuth, generateOtp);

    app.post("/api/login", handleLogin);

    app.get("/api/logout", checkAuth, handleLogout);

    app.get("/api/dashboard", checkAuth, dashboard);

    app.get("/api/otpForm", otpForm);

    app.post("/api/otp", checkAuth, verifyotp)



}

module.exports = {
    setupRoutes
};