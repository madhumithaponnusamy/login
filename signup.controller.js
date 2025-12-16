const db = require("../db/db");
const query = require("../controller/signup.query");
const sendMail = require("../mail/mail");
const { saveLog } = require("../logger/logger");
const hashPassword = require("../utils/hash");
const bcrypt = require("bcrypt");
const upload = require("../middleware/upload")
const path = require("path");
const fs = require("fs");


// ====================== SIGNUP ======================

function showSignup(req, res) {

    const edit = !!req.session.userId;

    if (edit) {

        return res.render("signup", {
            title: "Edit Profile",
            error: null,
            edit: true,
            user: {
                username: req.session.username,
                email: req.session.email,
                profilePath: req.session.profilePath
            }
        });
    }

    res.render("signup", {
        title: "Sign Up",
        error: null,
        edit: false,
        user: null
    });
}

async function signUpCheck(req, res) {


    const { username, password, confirmPassword, email } = req.body;
    const profile = req.file;


    // validation
    if (!username || !email || !password || !confirmPassword) {
        return res.status(400).json({
            success: false,
            error: "All fields are required"
        });
    }


    if (password !== confirmPassword) {
        return res.status(400).json({
            success: false,
            error: "Passwords do not match"
        });
    }

    if (!profile) {
        return res.status(400).json({
            success: false,
            title: "signup",
            error: "Profile image is required"
        });
    }

    const [rows] = await db.query(query.checkUserExists, [username, email]);
    if (rows.length > 0) {
        return res.json({
            success: false,
            error: "Username or Email already exists"
        });
    }


    try {
        const hash = await hashPassword(password);
        const profilePath = profile ? `/upload/${profile.filename}` : null;

        await db.query(query.insertUser, [
            username,
            email,
            hash,
            profilePath
        ]);

        req.session.profilePath = profilePath;

        return res.json({
            success: true,
            message: "Signup successful!",
            redirect: "/login"
        });

    } catch (err) {
        console.error("SIGNUP ERROR:", err);
        return res.status(500).json({
            success: false,
            error: err.message || "Server error"
        });
    }
}



async function updateProfile(req, res) {
    try {
        const userId = req.session.userId;

        if (!userId) {
            return res.status(401).json({ error: "Unauthorized" });
        }

        if (!req.file) {
            return res.status(400).json({ error: "No file uploaded" });
        }

        const newProfile = req.file.filename;

        // 1️⃣ get old profile image
        const [rows] = await db.query(
            query.getProfileByUserId,
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        const oldProfile = rows[0].profilePath;

        // 2️⃣ delete old image if exists
        if (oldProfile) {
            const oldPath = path.join(__dirname, "..", oldProfile);
            if (fs.existsSync(oldPath)) {
                fs.unlinkSync(oldPath);
            }
        }

        // 3️⃣ update db with new image
        await db.query(
            query.updateProfileByUserId,
            [newProfile, userId]
        );

        // 4️⃣ update session
        req.session.profilePath = newProfile;

        return res.json({
            success: true,
            redirect: "/dashboard"
        });

    } catch (err) {
        console.error("Update profile error:", err);
        return res.status(500).json({ error: "Profile update failed" });
    }
}








// ====================== LOGIN ======================

function loginform(req, res) {

    if (req.session.userId) {
        req.log.error("user aldready logged")
        return res.redirect("/dashboard");
    }
    res.render("login", {
        title: "Login Page",
        error: null
    });
}

async function logincheck(req, res) {
    const { username, password } = req.body;
    if (!username || !password) return res.json({ success: false, error: "All fields are required" });


    try {
        const [rows] = await db.query(query.getUser, [username]);

        if (rows.length === 0) {
            return res.json({ success: false, error: "Invalid username or password" });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({ success: false, error: "Invalid username or password" });
        }

        req.session.user = user;
        req.session.tempProfilePath = user.profilePath;

        const otp = Math.floor(100000 + Math.random() * 900000);
        req.session.otp = otp;
        req.session.twoFA = "pending";
        req.session.otpExpiry = Date.now() + 2 * 60 * 1000;
        req.session.otpAttempt = 0;


        console.log("Login OTP:", otp);

        await sendMail(user.email, "OTP for Login", `Your OTP is: ${otp}`);

        return res.json({ success: true, redirect: "/otp" });

    } catch (err) {
        console.error(err);
        return res.json({ success: false, error: "server error" });
    }
}

// ====================== OTP (Login) ======================

function showOtp(req, res) {
    // 1️⃣ Check that the session exists
    if (!req.session) {
        return res.redirect("/login");
    }

    // 2️⃣ Check that user has logged in and OTP is pending
    if (!req.session.user || req.session.twoFA !== "pending" || !req.session.otp) {
        // Clear any leftover session data
        delete req.session.user;
        delete req.session.twoFA;
        delete req.session.otp;
        delete req.session.otpExpiry;
        delete req.session.otpAttempt;

        return res.redirect("/login");
    }

    // 3️⃣ Check if OTP is expired
    if (Date.now() > req.session.otpExpiry) {
        // Clear expired OTP
        delete req.session.user;
        delete req.session.twoFA;
        delete req.session.otp;
        delete req.session.otpExpiry;
        delete req.session.otpAttempt;

        return res.redirect("/login");
    }

    res.render("otpForm", { error: null });
}


function verifyOtp(req, res) {

    if (
        !req.session ||
        !req.session.user ||
        !req.session.otp ||
        req.session.twoFA !== "pending"
    ) {
        return res.status(401).json({
            success: false,
            error: "Unauthorized access. Please login again.",
            redirect: "/login"
        });
    }

    const { otp } = req.body;

    // initialize attempt counter
    if (!req.session.otpAttempt) {
        req.session.otpAttempt = 0;
    }

    req.session.otpAttempt++;

    // rate limit check
    if (req.session.otpAttempt > 3) {
        req.session.destroy(() => { });
        return res.json({
            success: false,
            error: "Too many attempts. Please login again.",
            redirect: "/login"
        });
    }

    // OTP required
    if (!otp) {
        return res.status(400).json({
            success: false,
            title: "Verify OTP",
            error: "OTP is required"
        });
    }

    // OTP expired or missing
    if (!req.session.otp || Date.now() > req.session.otpExpiry) {
        return res.status(400).json({
            success: false,
            title: "Verify OTP",
            error: "OTP expired. Please login again.",
            redirect: "/login"
        });
    }

    // OTP mismatch
    if (otp.toString() !== req.session.otp.toString()) {
        return res.status(401).json({
            success: false,
            title: "Verify OTP",
            error: "Invalid OTP"
        });
    }

    // ✅ OTP correct → login success
    const user = req.session.user;

    req.session.userId = user.userId;
    req.session.username = user.username;
    req.session.email = user.email;
    req.session.profilePath = user.profilePath;
    req.session.twoFA = "verified";

    // cleanup
    delete req.session.otp;
    delete req.session.otpAttempt;
    delete req.session.otpExpiry;




    return res.json({
        success: true,
        redirect: "/dashboard"
    });
}


function showForgotPassword(req, res) {
    res.render("forgotPassword", {
        title: "forgot Password",
        error: null
    });
}



async function verifyForgotPassword(req, res) {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, error: "Email is required" });
    }

    try {
        const [rows] = await db.query(query.getUserByEmail, [email]);

        if (!rows || rows.length === 0) {
            return res.status(401).json({ success: false, error: "Email not registered" });
        }

        const user = rows[0];

        // reset old session
        delete req.session.forgotPasswordOtp;
        delete req.session.forgotPasswordOtpExpiry;
        delete req.session.forgotPasswordOtpAttempt;

        req.session.forgotPasswordUser = { id: user.id, email: user.email };

        const otp = Math.floor(100000 + Math.random() * 900000);
        req.session.forgotPasswordOtp = otp;
        req.session.forgotPasswordOtpExpiry = Date.now() + 5 * 60 * 1000;
        req.session.forgotPasswordOtpAttempt = 0;

        console.log("Forgot Password OTP:", otp);

        await sendMail(user.email, "Your OTP Code", `Your OTP is: ${otp}`);

        return res.status(200).json({ success: true, redirect: "/forgotPasswordOtp" });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ success: false, error: "Server error" });
    }
}




function showForgotPasswordOtp(req, res) {
    res.render("forgotPasswordOtp", { title: "Forgot Password OTP", error: null });
}

function forgotPasswordOtpVerify(req, res) {
    const { otp } = req.body;

    if (!req.session.forgotPasswordOtpAttempt) {
        req.session.forgotPasswordOtpAttempt = 0;
    }

    req.session.forgotPasswordOtpAttempt++;

    // Too many attempts → redirect to login
    if (req.session.forgotPasswordOtpAttempt > 3) {
        return res.status(429).json({
            success: false,
            redirect: "/login",
            error: "Too many attempts"
        });
    }

    // No OTP in session
    if (!req.session.forgotPasswordOtp) {
        return res.status(400).json({
            success: false,
            error: "OTP expired or not generated"
        });
    }

    // Invalid OTP
    if (String(otp) !== String(req.session.forgotPasswordOtp)) {
        return res.status(400).json({
            success: false,
            error: "Invalid OTP"
        });
    }
    if (Date.now() > req.session.forgotPasswordOtpExpiry) {
        return res.status(400).json({
            success: false,
            error: "OTP expired"
        });
    }


    // Correct OTP
    req.session.forgotPasswordVerified = true;
    req.session.forgotPasswordOtpAttempt = 0;

    return res.json({
        success: true,
        redirect: "/resetPassword"
    });
}

function showResetPassword(req, res) {
    res.render("resetPassword", {
        title: "reset password", error: null
    })
}

async function verifyResetPassword(req, res) {
    const { password, confirmPassword } = req.body

    if (!password || !confirmPassword) {
        return res.json({
            success: false,
            error: "All fields are required"
        });
    }

    if (password !== confirmPassword) {
        return res.json({
            success: false,
            error: "Passwords do not match"
        });
    }

    if (!req.session.forgotPasswordVerified) {
        return res.status(403).json({
            success: false,
            error: "Unauthorized reset attempt"
        });
    }

    try {
        // hash the new password
        const hash = await hashPassword(password);

        const email = req.session.forgotPasswordUser.email;

        await req.db.promise().execute(query.updatePasswordByEmail, [hash, email]);

        // clear the forgot password session data
        delete req.session.forgotPasswordUser;
        delete req.session.forgotPasswordVerified;

        return res.json({
            success: true,
            title: "Reset password",
            redirect: "/login"
        });


    } catch (err) {
        req.log.error("Hashing error during reset password", err);
        return res.status(500).json({
            success: false,
            title: "reset password",
            error: "Server error"
        });
    }

}

// ====================== DASHBOARD + LOGOUT ======================

function showDashboard(req, res) {

    if (!req.session.userId) {
        return res.redirect("/login");
    }

    res.render("dashboard", {
        title: "Dashboard",
        user: {
            username: req.session.username,
            email: req.session.email,
            profilePath: req.session.profilePath
        }
    });
}



function logout(req, res) {
    req.session.destroy(() => res.redirect("/login"));
}

// ====================== ROUTES ======================

function setUpRoutes(app) {
    app.get("/", (req, res) => res.redirect("/login"));
    app.get("/login", loginform);
    app.get("/signup", showSignup);
    app.get("/forgotPassword", showForgotPassword)
    app.get("/forgotPasswordOtp", showForgotPasswordOtp)
    app.get("/resetPassword", showResetPassword)

    // Login OTP
    app.get("/otp", showOtp);


    // APIs
    app.post("/api/authsystem/signup", upload.single("profile"), signUpCheck)
    app.post("/api/authsystem/checklogin", logincheck);
    app.post("/api/authsystem/otpverify", verifyOtp);
    app.post("/api/verifyForgotPassword", verifyForgotPassword)
    app.post("/api/forgotPasswordOtpVerify", forgotPasswordOtpVerify)
    app.post("/api/updateProfile", upload.single("profile"), updateProfile)


    app.put("/api/resetPassword", verifyResetPassword)

    app.get("/dashboard", showDashboard);
    app.get("/logout", logout);
}


module.exports = { setUpRoutes };