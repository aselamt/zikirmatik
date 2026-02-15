function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  return next();
}

function requireGuest(req, res, next) {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  if (req.session.user.role !== 'admin') {
    return res.status(403).render('error', {
      title: 'Yetkisiz',
      message: 'Bu sayfaya erisim yetkiniz yok.',
      user: req.session.user,
    });
  }

  return next();
}

module.exports = {
  requireAuth,
  requireGuest,
  requireAdmin,
};
