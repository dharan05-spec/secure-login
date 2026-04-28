function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  req.session.flash = { type: 'error', message: 'Please log in to access this page.' };
  res.redirect('/login');
}

function requireGuest(req, res, next) {
  if (req.session && req.session.userId) return res.redirect('/dashboard');
  next();
}

module.exports = { requireAuth, requireGuest };
