const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStoreFactory = require('connect-sqlite3');
const bcrypt = require('bcryptjs');

const { initDb } = require('./db');
const { requireAuth, requireGuest, requireAdmin } = require('./middleware');

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'zikirmatik-dev-secret-change-me';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin12345';

async function ensureDefaultAdmin(db) {
  const existing = await db.get('SELECT id FROM users WHERE username = ?', ADMIN_USERNAME);
  if (existing) {
    return;
  }

  const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  await db.run(
    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
    ADMIN_USERNAME,
    hash,
    'admin'
  );

  // eslint-disable-next-line no-console
  console.log(`Varsayilan admin olusturuldu -> kullanici: ${ADMIN_USERNAME}`);
}

async function main() {
  const db = await initDb();
  await ensureDefaultAdmin(db);

  const app = express();
  const SQLiteStore = SQLiteStoreFactory(session);

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));

  app.use(express.urlencoded({ extended: false }));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(
    session({
      store: new SQLiteStore({
        db: 'sessions.sqlite',
        dir: path.join(__dirname, '..'),
      }),
      secret: SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 7,
      },
    })
  );

  app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.error = null;
    res.locals.success = null;
    next();
  });

  app.get('/', (req, res) => {
    if (req.session.user) {
      return res.redirect('/dashboard');
    }
    return res.redirect('/login');
  });

  app.get('/login', requireGuest, (req, res) => {
    res.render('login', { title: 'Giris Yap', error: null });
  });

  app.post('/login', requireGuest, async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).render('login', {
        title: 'Giris Yap',
        error: 'Kullanici adi ve sifre zorunludur.',
      });
    }

    const user = await db.get('SELECT * FROM users WHERE username = ?', username.trim());

    if (!user) {
      return res.status(401).render('login', {
        title: 'Giris Yap',
        error: 'Kullanici adi veya sifre hatali.',
      });
    }

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).render('login', {
        title: 'Giris Yap',
        error: 'Kullanici adi veya sifre hatali.',
      });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
    };

    return res.redirect('/dashboard');
  });

  app.get('/register', requireGuest, (req, res) => {
    res.render('register', { title: 'Uye Ol', error: null });
  });

  app.post('/register', requireGuest, async (req, res) => {
    const { username, password, passwordConfirm } = req.body;

    if (!username || !password || !passwordConfirm) {
      return res.status(400).render('register', {
        title: 'Uye Ol',
        error: 'Tum alanlar zorunludur.',
      });
    }

    if (password.length < 6) {
      return res.status(400).render('register', {
        title: 'Uye Ol',
        error: 'Sifre en az 6 karakter olmali.',
      });
    }

    if (password !== passwordConfirm) {
      return res.status(400).render('register', {
        title: 'Uye Ol',
        error: 'Sifreler eslesmiyor.',
      });
    }

    const cleanedUsername = username.trim();
    const exists = await db.get('SELECT id FROM users WHERE username = ?', cleanedUsername);
    if (exists) {
      return res.status(409).render('register', {
        title: 'Uye Ol',
        error: 'Bu kullanici adi zaten alinmis.',
      });
    }

    const hash = await bcrypt.hash(password, 10);
    const result = await db.run(
      'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
      cleanedUsername,
      hash,
      'user'
    );

    req.session.user = {
      id: result.lastID,
      username: cleanedUsername,
      role: 'user',
    };

    return res.redirect('/dashboard');
  });

  app.post('/logout', requireAuth, (req, res) => {
    req.session.destroy(() => {
      res.redirect('/login');
    });
  });

  app.get('/dashboard', requireAuth, async (req, res) => {
    const userZikirs = await db.all(
      `SELECT id, title, description, target_count, current_count, created_at
       FROM user_zikirs
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      req.session.user.id
    );

    const presets = await db.all(
      `SELECT p.id, p.title, p.description, p.target_count, p.created_at, u.username AS creator
       FROM preset_zikirs p
       LEFT JOIN users u ON p.created_by = u.id
       ORDER BY p.created_at DESC`
    );

    return res.render('dashboard', {
      title: 'Panelim',
      userZikirs,
      presets,
      success: req.query.success || null,
      error: req.query.error || null,
    });
  });

  app.post('/zikirs', requireAuth, async (req, res) => {
    const { title, description, targetCount } = req.body;
    const parsedTarget = Number.parseInt(targetCount, 10);

    if (!title || Number.isNaN(parsedTarget) || parsedTarget <= 0) {
      return res.redirect('/dashboard?error=Baslik ve gecerli hedef adet zorunludur.');
    }

    await db.run(
      `INSERT INTO user_zikirs (user_id, title, description, target_count, current_count)
       VALUES (?, ?, ?, ?, 0)`,
      req.session.user.id,
      title.trim(),
      (description || '').trim(),
      parsedTarget
    );

    return res.redirect('/dashboard?success=Zikir eklendi.');
  });

  app.post('/zikirs/:id/increment', requireAuth, async (req, res) => {
    const zikrId = Number.parseInt(req.params.id, 10);
    const wantsJson =
      req.query.ajax === '1' ||
      req.xhr ||
      req.headers.accept?.includes('application/json');

    if (Number.isNaN(zikrId)) {
      if (wantsJson) {
        return res.status(400).json({ error: 'Gecersiz zikir.' });
      }
      return res.redirect('/dashboard?error=Gecersiz zikir.');
    }

    await db.run(
      `UPDATE user_zikirs
       SET current_count = CASE
         WHEN current_count < target_count THEN current_count + 1
         ELSE current_count
       END
       WHERE id = ? AND user_id = ?`,
      zikrId,
      req.session.user.id
    );

    if (wantsJson) {
      const row = await db.get(
        `SELECT id, current_count, target_count
         FROM user_zikirs
         WHERE id = ? AND user_id = ?`,
        zikrId,
        req.session.user.id
      );

      if (!row) {
        return res.status(404).json({ error: 'Zikir bulunamadi.' });
      }

      return res.json({
        id: row.id,
        currentCount: row.current_count,
        targetCount: row.target_count,
      });
    }

    const row = await db.get(
      `SELECT id
       FROM user_zikirs
       WHERE id = ? AND user_id = ?`,
      zikrId,
      req.session.user.id
    );

    if (!row) {
      if (wantsJson) {
        return res.status(404).json({ error: 'Zikir bulunamadi.' });
      }
      return res.redirect('/dashboard?error=Zikir bulunamadi.');
    }

    return res.redirect('/dashboard');
  });

  app.post('/zikirs/:id/decrement', requireAuth, async (req, res) => {
    const zikrId = Number.parseInt(req.params.id, 10);
    const wantsJson =
      req.query.ajax === '1' ||
      req.xhr ||
      req.headers.accept?.includes('application/json');

    if (Number.isNaN(zikrId)) {
      if (wantsJson) {
        return res.status(400).json({ error: 'Gecersiz zikir.' });
      }
      return res.redirect('/dashboard?error=Gecersiz zikir.');
    }

    await db.run(
      `UPDATE user_zikirs
       SET current_count = CASE WHEN current_count > 0 THEN current_count - 1 ELSE 0 END
       WHERE id = ? AND user_id = ?`,
      zikrId,
      req.session.user.id
    );

    if (wantsJson) {
      const row = await db.get(
        `SELECT id, current_count, target_count
         FROM user_zikirs
         WHERE id = ? AND user_id = ?`,
        zikrId,
        req.session.user.id
      );

      if (!row) {
        return res.status(404).json({ error: 'Zikir bulunamadi.' });
      }

      return res.json({
        id: row.id,
        currentCount: row.current_count,
        targetCount: row.target_count,
      });
    }

    return res.redirect('/dashboard');
  });

  app.post('/zikirs/:id/reset', requireAuth, async (req, res) => {
    const zikrId = Number.parseInt(req.params.id, 10);
    const wantsJson =
      req.query.ajax === '1' ||
      req.xhr ||
      req.headers.accept?.includes('application/json');

    if (Number.isNaN(zikrId)) {
      if (wantsJson) {
        return res.status(400).json({ error: 'Gecersiz zikir.' });
      }
      return res.redirect('/dashboard?error=Gecersiz zikir.');
    }

    await db.run(
      `UPDATE user_zikirs
       SET current_count = 0
       WHERE id = ? AND user_id = ?`,
      zikrId,
      req.session.user.id
    );

    if (wantsJson) {
      const row = await db.get(
        `SELECT id, current_count, target_count
         FROM user_zikirs
         WHERE id = ? AND user_id = ?`,
        zikrId,
        req.session.user.id
      );

      if (!row) {
        return res.status(404).json({ error: 'Zikir bulunamadi.' });
      }

      return res.json({
        id: row.id,
        currentCount: row.current_count,
        targetCount: row.target_count,
      });
    }

    return res.redirect('/dashboard');
  });

  app.post('/zikirs/:id/delete', requireAuth, async (req, res) => {
    const zikrId = Number.parseInt(req.params.id, 10);
    if (Number.isNaN(zikrId)) {
      return res.redirect('/dashboard?error=Gecersiz zikir.');
    }

    await db.run('DELETE FROM user_zikirs WHERE id = ? AND user_id = ?', zikrId, req.session.user.id);
    return res.redirect('/dashboard?success=Zikir silindi.');
  });

  app.post('/presets/:id/add', requireAuth, async (req, res) => {
    const presetId = Number.parseInt(req.params.id, 10);
    if (Number.isNaN(presetId)) {
      return res.redirect('/dashboard?error=Gecersiz hazir zikir.');
    }

    const preset = await db.get('SELECT * FROM preset_zikirs WHERE id = ?', presetId);
    if (!preset) {
      return res.redirect('/dashboard?error=Hazir zikir bulunamadi.');
    }

    await db.run(
      `INSERT INTO user_zikirs (user_id, title, description, target_count, current_count, source_preset_id)
       VALUES (?, ?, ?, ?, 0, ?)`,
      req.session.user.id,
      preset.title,
      preset.description || '',
      preset.target_count,
      preset.id
    );

    return res.redirect('/dashboard?success=Hazir zikir paneline eklendi.');
  });

  app.get('/admin', requireAdmin, async (req, res) => {
    const presets = await db.all(
      `SELECT p.id, p.title, p.description, p.target_count, p.created_at, u.username AS creator
       FROM preset_zikirs p
       LEFT JOIN users u ON p.created_by = u.id
       ORDER BY p.created_at DESC`
    );

    return res.render('admin', {
      title: 'Admin Paneli',
      presets,
      success: req.query.success || null,
      error: req.query.error || null,
    });
  });

  app.post('/admin/presets', requireAdmin, async (req, res) => {
    const { title, description, targetCount } = req.body;
    const parsedTarget = Number.parseInt(targetCount, 10);

    if (!title || Number.isNaN(parsedTarget) || parsedTarget <= 0) {
      return res.redirect('/admin?error=Baslik ve gecerli hedef adet zorunludur.');
    }

    await db.run(
      `INSERT INTO preset_zikirs (title, description, target_count, created_by)
       VALUES (?, ?, ?, ?)`,
      title.trim(),
      (description || '').trim(),
      parsedTarget,
      req.session.user.id
    );

    return res.redirect('/admin?success=Hazir zikir eklendi.');
  });

  app.post('/admin/presets/:id/delete', requireAdmin, async (req, res) => {
    const presetId = Number.parseInt(req.params.id, 10);
    if (Number.isNaN(presetId)) {
      return res.redirect('/admin?error=Gecersiz kayit.');
    }

    await db.run('DELETE FROM preset_zikirs WHERE id = ?', presetId);
    return res.redirect('/admin?success=Hazir zikir silindi.');
  });

  app.use((req, res) => {
    res.status(404).render('error', {
      title: 'Bulunamadi',
      message: 'Aradiginiz sayfa bulunamadi.',
      user: req.session.user || null,
    });
  });

  app.use((err, req, res, next) => {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).render('error', {
      title: 'Sunucu Hatasi',
      message: 'Beklenmeyen bir hata olustu.',
      user: req.session.user || null,
    });
  });

  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Zikirmatik uygulamasi calisiyor: http://localhost:${PORT}`);
  });
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error('Uygulama baslatilamadi:', error);
  process.exit(1);
});
