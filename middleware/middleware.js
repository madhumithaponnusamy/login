const publicRoutes = ['/api/loginpage', '/api/login'];

function checkAuth(req, res, next) {
    if (publicRoutes.includes(req.path)) {
        return next();
    }

    if (req.session.userId) {
        console.log(`[AUTH] User ${req.session.userId} accessing ${req.method} ${req.url}`);
        return next();
    }

    console.log(`[AUTH] Unauthenticated access attempt: ${req.method} ${req.url}`);
    res.redirect("/api/loginpage");
}

function AlreadyLoggedIn(req, res, next) {
    if ( req.session.userId) {
        return res.redirect("/api/dashboard");
    }
    next();
}

module.exports = {
  checkAuth,
  AlreadyLoggedIn
};