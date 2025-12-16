function isAuthenticated(req, res, next) {

    if (req.path === "/api/authsystem/otpverify" || req.path === "/otp") {
        if (!req.session.user) {
            return res.redirect("/login");
        }
        return next();
    }

    if (!req.session.user || req.session.twoFA !== "verified") {
        return res.redirect("/login");
    }

    next();
}

function alreadyLoggedIn(req, res, next) {

    if (req.session.user && req.session.twoFA === "verified" &&
        req.query.edit !== "true") {
        return res.redirect("/dashboard");
    }
    next();
}

module.exports = { isAuthenticated, alreadyLoggedIn };
