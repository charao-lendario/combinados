import express from 'express';
import cors from 'cors';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

const { Pool } = pg;

// ============================================
// CONFIG
// ============================================
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'combinados-jwt-secret-2024-change-in-production';
const JWT_EXPIRES_IN = '7d';
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/var/uploads/combinados';

const pool = new Pool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'combinados',
  user: process.env.DB_USER || 'combinados_user',
  password: process.env.DB_PASSWORD || 'Comb1nad0s_2024!Sec',
});

// Ensure upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => {
      const unique = `${Date.now()}-${uuidv4()}`;
      cb(null, `${unique}-${file.originalname}`);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

const app = express();
app.use(cors());
app.use(express.json());

// ============================================
// AUTH MIDDLEWARE
// ============================================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
    } catch { /* ignore */ }
  }
  next();
}

// ============================================
// AUTH ROUTES
// ============================================

// Sign Up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, options } = req.body;
    const metadata = options?.data || {};

    // Check if email exists
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: { message: 'Usuário já cadastrado com este email' } });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    // Insert user - trigger will create profile and role
    await pool.query(
      `INSERT INTO users (id, email, password_hash, raw_user_meta_data, email_confirmed_at)
       VALUES ($1, $2, $3, $4, now())`,
      [userId, email, passwordHash, JSON.stringify(metadata)]
    );

    const user = {
      id: userId,
      email,
      user_metadata: metadata,
      created_at: new Date().toISOString(),
    };

    res.json({ data: { user, session: null }, error: null });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: { message: err.message } });
  }
});

// Sign In
app.post('/api/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      'SELECT id, email, password_hash, raw_user_meta_data FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: { message: 'Credenciais inválidas' } });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(400).json({ error: { message: 'Credenciais inválidas' } });
    }

    // Update last login
    await pool.query('UPDATE profiles SET last_login_at = now() WHERE id = $1', [user.id]);

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    const refreshToken = jwt.sign({ id: user.id, type: 'refresh' }, JWT_SECRET, { expiresIn: '30d' });

    // Save session
    await pool.query(
      `INSERT INTO sessions (user_id, token, refresh_token, expires_at)
       VALUES ($1, $2, $3, now() + interval '7 days')`,
      [user.id, token, refreshToken]
    );

    const userData = {
      id: user.id,
      email: user.email,
      user_metadata: user.raw_user_meta_data || {},
    };

    res.json({
      data: {
        user: userData,
        session: {
          access_token: token,
          refresh_token: refreshToken,
          user: userData,
        },
      },
      error: null,
    });
  } catch (err) {
    console.error('Signin error:', err);
    res.status(500).json({ error: { message: err.message } });
  }
});

// Sign Out
app.post('/api/auth/signout', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [req.user.id]);
    res.json({ error: null });
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

// Get Session
app.get('/api/auth/session', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, raw_user_meta_data FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) {
      return res.json({ data: { session: null }, error: null });
    }
    const user = result.rows[0];
    const token = req.headers['authorization'].split(' ')[1];

    res.json({
      data: {
        session: {
          access_token: token,
          user: {
            id: user.id,
            email: user.email,
            user_metadata: user.raw_user_meta_data || {},
          },
        },
      },
      error: null,
    });
  } catch (err) {
    res.json({ data: { session: null }, error: null });
  }
});

// Get User
app.get('/api/auth/user', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, raw_user_meta_data FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) {
      return res.json({ data: { user: null }, error: { message: 'User not found' } });
    }
    const user = result.rows[0];
    res.json({
      data: {
        user: {
          id: user.id,
          email: user.email,
          user_metadata: user.raw_user_meta_data || {},
        },
      },
      error: null,
    });
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

// Update User (password change)
app.put('/api/auth/user', authenticateToken, async (req, res) => {
  try {
    const { password } = req.body;
    if (password) {
      const passwordHash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, req.user.id]);
    }
    const result = await pool.query(
      'SELECT id, email, raw_user_meta_data FROM users WHERE id = $1',
      [req.user.id]
    );
    const user = result.rows[0];
    res.json({
      data: {
        user: {
          id: user.id,
          email: user.email,
          user_metadata: user.raw_user_meta_data || {},
        },
      },
      error: null,
    });
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

// ============================================
// GENERIC DB ROUTES (replaces supabase.from())
// ============================================

const ALLOWED_TABLES = [
  'profiles', 'user_roles', 'agreements', 'agreement_participants',
  'checklist_items', 'attachments', 'comments', 'notifications',
  'audit_logs', 'workspaces', 'team_members',
];

// SELECT
app.post('/api/db/:table/select', authenticateToken, async (req, res) => {
  try {
    const { table } = req.params;
    if (!ALLOWED_TABLES.includes(table)) {
      return res.status(400).json({ error: { message: `Table ${table} not allowed` } });
    }

    const { columns, filters, order, limit, single, count, or: orFilter } = req.body;
    const cols = columns || '*';

    let query = `SELECT ${cols} FROM ${table}`;
    const values = [];
    const conditions = [];

    if (filters && filters.length > 0) {
      for (const f of filters) {
        const idx = values.length + 1;
        if (f.op === 'eq') {
          conditions.push(`${f.column} = $${idx}`);
          values.push(f.value);
        } else if (f.op === 'neq') {
          conditions.push(`${f.column} != $${idx}`);
          values.push(f.value);
        } else if (f.op === 'in') {
          const placeholders = f.value.map((_, i) => `$${values.length + i + 1}`);
          conditions.push(`${f.column} IN (${placeholders.join(',')})`);
          values.push(...f.value);
        } else if (f.op === 'is') {
          if (f.value === null) {
            conditions.push(`${f.column} IS NULL`);
          } else {
            conditions.push(`${f.column} IS $${idx}`);
            values.push(f.value);
          }
        }
      }
    }

    if (orFilter) {
      // Handle OR filter string like "creator_id.eq.xxx,agreement_id.in.(a,b,c)"
      conditions.push(`(${orFilter})`);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    if (order) {
      const orderParts = order.map(o => `${o.column} ${o.ascending === false ? 'DESC' : 'ASC'}`);
      query += ' ORDER BY ' + orderParts.join(', ');
    }

    if (limit) {
      query += ` LIMIT ${parseInt(limit)}`;
    }

    const result = await pool.query(query, values);

    if (single) {
      res.json({ data: result.rows[0] || null, error: null, count: result.rowCount });
    } else if (count) {
      res.json({ data: result.rows, error: null, count: result.rowCount });
    } else {
      res.json({ data: result.rows, error: null });
    }
  } catch (err) {
    console.error('Select error:', err);
    res.status(500).json({ data: null, error: { message: err.message } });
  }
});

// INSERT
app.post('/api/db/:table/insert', authenticateToken, async (req, res) => {
  try {
    const { table } = req.params;
    if (!ALLOWED_TABLES.includes(table)) {
      return res.status(400).json({ error: { message: `Table ${table} not allowed` } });
    }

    const { data, returning } = req.body;
    const rows = Array.isArray(data) ? data : [data];

    if (rows.length === 0) {
      return res.json({ data: [], error: null });
    }

    const allResults = [];

    for (const row of rows) {
      const columns = Object.keys(row);
      const values = Object.values(row);
      const placeholders = columns.map((_, i) => `$${i + 1}`);

      const query = `INSERT INTO ${table} (${columns.join(',')}) VALUES (${placeholders.join(',')}) RETURNING *`;
      const result = await pool.query(query, values);
      allResults.push(result.rows[0]);
    }

    if (returning === 'single') {
      res.json({ data: allResults[0], error: null });
    } else {
      res.json({ data: Array.isArray(req.body.data) ? allResults : allResults[0], error: null });
    }
  } catch (err) {
    console.error('Insert error:', err);
    res.status(500).json({ data: null, error: { message: err.message } });
  }
});

// UPDATE
app.post('/api/db/:table/update', authenticateToken, async (req, res) => {
  try {
    const { table } = req.params;
    if (!ALLOWED_TABLES.includes(table)) {
      return res.status(400).json({ error: { message: `Table ${table} not allowed` } });
    }

    const { data, filters } = req.body;
    const setCols = Object.keys(data);
    const setValues = Object.values(data);
    const setClause = setCols.map((col, i) => `${col} = $${i + 1}`).join(', ');

    let query = `UPDATE ${table} SET ${setClause}`;
    const values = [...setValues];

    if (filters && filters.length > 0) {
      const conditions = filters.map((f, i) => {
        const idx = values.length + 1;
        values.push(f.value);
        return `${f.column} = $${idx}`;
      });
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' RETURNING *';
    const result = await pool.query(query, values);
    res.json({ data: result.rows, error: null });
  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ data: null, error: { message: err.message } });
  }
});

// DELETE
app.post('/api/db/:table/delete', authenticateToken, async (req, res) => {
  try {
    const { table } = req.params;
    if (!ALLOWED_TABLES.includes(table)) {
      return res.status(400).json({ error: { message: `Table ${table} not allowed` } });
    }

    const { filters } = req.body;
    let query = `DELETE FROM ${table}`;
    const values = [];

    if (filters && filters.length > 0) {
      const conditions = filters.map((f) => {
        const idx = values.length + 1;
        values.push(f.value);
        return `${f.column} = $${idx}`;
      });
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' RETURNING *';
    const result = await pool.query(query, values);
    res.json({ data: result.rows, error: null });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ data: null, error: { message: err.message } });
  }
});

// UPSERT
app.post('/api/db/:table/upsert', authenticateToken, async (req, res) => {
  try {
    const { table } = req.params;
    if (!ALLOWED_TABLES.includes(table)) {
      return res.status(400).json({ error: { message: `Table ${table} not allowed` } });
    }

    const { data, onConflict } = req.body;
    const rows = Array.isArray(data) ? data : [data];
    const allResults = [];

    for (const row of rows) {
      const columns = Object.keys(row);
      const values = Object.values(row);
      const placeholders = columns.map((_, i) => `$${i + 1}`);
      const updateCols = columns.filter(c => c !== 'id' && !onConflict?.includes(c));
      const updateClause = updateCols.map(c => `${c} = EXCLUDED.${c}`).join(', ');

      let conflictTarget = onConflict || 'id';
      if (Array.isArray(conflictTarget)) conflictTarget = conflictTarget.join(',');

      let query = `INSERT INTO ${table} (${columns.join(',')}) VALUES (${placeholders.join(',')})`;
      if (updateClause) {
        query += ` ON CONFLICT (${conflictTarget}) DO UPDATE SET ${updateClause}`;
      } else {
        query += ` ON CONFLICT (${conflictTarget}) DO NOTHING`;
      }
      query += ' RETURNING *';

      const result = await pool.query(query, values);
      allResults.push(result.rows[0]);
    }

    res.json({ data: Array.isArray(req.body.data) ? allResults : allResults[0], error: null });
  } catch (err) {
    console.error('Upsert error:', err);
    res.status(500).json({ data: null, error: { message: err.message } });
  }
});

// ============================================
// RPC ROUTES
// ============================================
app.post('/api/rpc/:fn', authenticateToken, async (req, res) => {
  try {
    const { fn } = req.params;
    const args = req.body;

    const allowedFns = [
      'add_user_to_workspace_v2', 'remove_user_from_workspace',
      'add_user_to_workspace_by_email', 'get_user_workspace_id',
      'has_role', 'get_user_roles', 'can_access_agreement',
    ];

    if (!allowedFns.includes(fn)) {
      return res.status(400).json({ error: { message: `Function ${fn} not allowed` } });
    }

    const paramNames = Object.keys(args);
    const paramValues = Object.values(args);
    const placeholders = paramNames.map((_, i) => `$${i + 1}`);

    let query;
    if (paramNames.length > 0) {
      const namedParams = paramNames.map((name, i) => `${name} := $${i + 1}`).join(', ');
      query = `SELECT ${fn}(${namedParams})`;
    } else {
      query = `SELECT ${fn}()`;
    }

    const result = await pool.query(query, paramValues);
    res.json({ data: result.rows[0]?.[fn] ?? null, error: null });
  } catch (err) {
    console.error('RPC error:', err);
    res.status(500).json({ data: null, error: { message: err.message } });
  }
});

// ============================================
// STORAGE ROUTES
// ============================================

// Upload
app.post('/api/storage/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: { message: 'No file uploaded' } });
    }
    const storagePath = req.file.filename;
    res.json({
      data: { path: storagePath, fullPath: storagePath },
      error: null,
    });
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

// Download / Signed URL (serves file directly)
app.get('/api/storage/file/:filename', optionalAuth, async (req, res) => {
  try {
    const filePath = path.join(UPLOAD_DIR, req.params.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: { message: 'File not found' } });
    }
    res.sendFile(filePath);
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

// Create signed URL (returns a direct link)
app.post('/api/storage/signed-url', authenticateToken, async (req, res) => {
  try {
    const { path: storagePath } = req.body;
    const signedUrl = `/api/storage/file/${encodeURIComponent(storagePath)}`;
    res.json({ data: { signedUrl }, error: null });
  } catch (err) {
    res.status(500).json({ error: { message: err.message } });
  }
});

// ============================================
// QUERY WITH RELATIONS (replaces Supabase nested selects)
// ============================================
app.post('/api/db/:table/query', authenticateToken, async (req, res) => {
  try {
    const { table } = req.params;
    if (!ALLOWED_TABLES.includes(table)) {
      return res.status(400).json({ error: { message: `Table ${table} not allowed` } });
    }

    const { sql, params } = req.body;

    // Only allow SELECT queries for safety
    if (!sql.trim().toUpperCase().startsWith('SELECT')) {
      return res.status(400).json({ error: { message: 'Only SELECT queries allowed' } });
    }

    const result = await pool.query(sql, params || []);
    res.json({ data: result.rows, error: null });
  } catch (err) {
    console.error('Query error:', err);
    res.status(500).json({ data: null, error: { message: err.message } });
  }
});

// ============================================
// COMPOUND QUERY ROUTES (replaces Supabase nested selects)
// ============================================

// Profile with workspace name
app.get('/api/compound/profile/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query(
      `SELECT p.*, w.name as workspace_name
       FROM profiles p
       LEFT JOIN workspaces w ON w.id = p.workspace_id
       WHERE p.id = $1`,
      [userId]
    );
    if (result.rows.length === 0) {
      return res.json({ data: null, error: { message: 'Profile not found' } });
    }
    const row = result.rows[0];
    // Mimic Supabase nested format
    row.workspaces = row.workspace_name ? { name: row.workspace_name } : null;
    delete row.workspace_name;
    res.json({ data: row, error: null });
  } catch (err) {
    res.status(500).json({ data: null, error: { message: err.message } });
  }
});

// Agreements list with participant count + OR filter
app.post('/api/compound/agreements/list', authenticateToken, async (req, res) => {
  try {
    const { userId, participationIds, orderBy, orderAsc } = req.body;

    let query = `
      SELECT a.*,
        (SELECT COUNT(*) FROM agreement_participants ap WHERE ap.agreement_id = a.id) as participant_count
      FROM agreements a
    `;

    const values = [];
    if (participationIds && participationIds.length > 0) {
      values.push(userId);
      const placeholders = participationIds.map((_, i) => `$${i + 2}`);
      values.push(...participationIds);
      query += ` WHERE a.creator_id = $1 OR a.id IN (${placeholders.join(',')})`;
    } else {
      values.push(userId);
      query += ` WHERE a.creator_id = $1`;
    }

    const dir = orderAsc === false ? 'DESC' : 'ASC';
    query += ` ORDER BY ${orderBy || 'created_at'} ${dir}`;

    const result = await pool.query(query, values);

    // Format to match Supabase nested select format
    const data = result.rows.map(row => ({
      ...row,
      agreement_participants: [{ count: parseInt(row.participant_count) }],
    }));
    data.forEach(d => delete d.participant_count);

    res.json({ data, error: null });
  } catch (err) {
    console.error('Compound agreements list error:', err);
    res.status(500).json({ data: null, error: { message: err.message } });
  }
});

// Agreement full details with participants (+ profiles), checklist items, attachments
app.get('/api/compound/agreements/:id/full', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Get agreement
    const agResult = await pool.query('SELECT * FROM agreements WHERE id = $1', [id]);
    if (agResult.rows.length === 0) {
      return res.json({ data: null, error: { message: 'Agreement not found' } });
    }
    const agreement = agResult.rows[0];

    // Get participants with profiles
    const partResult = await pool.query(
      `SELECT ap.id, ap.user_id, ap.status, ap.response_date, ap.rejection_reason,
              p.full_name, p.position, p.avatar_url
       FROM agreement_participants ap
       LEFT JOIN profiles p ON p.id = ap.user_id
       WHERE ap.agreement_id = $1`,
      [id]
    );
    agreement.agreement_participants = partResult.rows.map(row => ({
      id: row.id,
      user_id: row.user_id,
      status: row.status,
      response_date: row.response_date,
      rejection_reason: row.rejection_reason,
      profiles: {
        full_name: row.full_name,
        position: row.position,
        avatar_url: row.avatar_url,
      },
    }));

    // Get checklist items
    const checkResult = await pool.query(
      'SELECT * FROM checklist_items WHERE agreement_id = $1 ORDER BY order_index',
      [id]
    );
    agreement.checklist_items = checkResult.rows;

    // Get attachments
    const attResult = await pool.query(
      'SELECT * FROM attachments WHERE agreement_id = $1',
      [id]
    );
    agreement.attachments = attResult.rows;

    res.json({ data: agreement, error: null });
  } catch (err) {
    console.error('Agreement full error:', err);
    res.status(500).json({ data: null, error: { message: err.message } });
  }
});

// Reports: agreements with creator workspace + participants with profiles
app.post('/api/compound/reports/agreements', authenticateToken, async (req, res) => {
  try {
    // Get all agreements with creator workspace_id
    const agResult = await pool.query(
      `SELECT a.*, p.workspace_id as creator_workspace_id
       FROM agreements a
       LEFT JOIN profiles p ON p.id = a.creator_id
       ORDER BY a.created_at DESC`
    );

    const agreements = agResult.rows;

    // Get all participants with profiles for these agreements
    const agIds = agreements.map(a => a.id);
    if (agIds.length > 0) {
      const placeholders = agIds.map((_, i) => `$${i + 1}`);
      const partResult = await pool.query(
        `SELECT ap.*, pr.full_name
         FROM agreement_participants ap
         LEFT JOIN profiles pr ON pr.id = ap.user_id
         WHERE ap.agreement_id IN (${placeholders.join(',')})`,
        agIds
      );

      // Group participants by agreement
      const partsByAgreement = {};
      for (const p of partResult.rows) {
        if (!partsByAgreement[p.agreement_id]) partsByAgreement[p.agreement_id] = [];
        partsByAgreement[p.agreement_id].push({
          ...p,
          profiles: { full_name: p.full_name },
        });
      }

      for (const ag of agreements) {
        ag.creator = { workspace_id: ag.creator_workspace_id };
        delete ag.creator_workspace_id;
        ag.agreement_participants = partsByAgreement[ag.id] || [];
      }
    }

    res.json({ data: agreements, error: null });
  } catch (err) {
    console.error('Reports error:', err);
    res.status(500).json({ data: null, error: { message: err.message } });
  }
});

// ============================================
// HEALTH CHECK
// ============================================
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', database: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'error', database: 'disconnected', message: err.message });
  }
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Combinados API running on port ${PORT}`);
});
