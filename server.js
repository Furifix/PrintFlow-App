// PrintFlow — Express backend (server.js)
// Proxies all Printify API calls. Serves built frontend in production.
// Port: 3005 (3000 and 3001 are occupied)
//
// TODO(security): Rate limiting not implemented — this is a local-only tool
//   with no user accounts. Add express-rate-limit if exposed to a network.
// TODO(security): No authentication — local-only tool, single operator.
// TODO(security): Antivirus scanning on uploaded images not implemented.

import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';
import fetch from 'node-fetch';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import os from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app  = express();
const PORT = process.env.PORT || 3005;

// Security middleware
app.use(helmet());

// Basic rate limiting: protect from accidental abuse. Tweak limits as needed.
const limiter = rateLimit({ windowMs: 60 * 1000, max: 120 }); // 120 req/min per IP
app.use(limiter);

// ─── Directory setup ──────────────────────────────────────────────────────────
const DATA_DIR        = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.resolve(path.join(__dirname, 'data'));
const UPLOADS_DIR     = process.env.UPLOADS_DIR ? path.resolve(process.env.UPLOADS_DIR) : path.resolve(path.join(__dirname, 'uploads', 'backgrounds'));
const SETTINGS_FILE   = path.resolve(path.join(DATA_DIR, 'settings.json'));
const HISTORY_FILE    = path.resolve(path.join(DATA_DIR, 'history.json'));
const MOCKUPS_DIR     = path.resolve(path.join(DATA_DIR, 'mockups'));
const ARCHIVED_MOCKUPS_DIR = path.resolve(path.join(MOCKUPS_DIR, 'archived'));
const JOBS_FILE       = path.resolve(path.join(DATA_DIR, 'jobs.json'));

function validateDataPath(filePath) {
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(DATA_DIR + path.sep) && resolved !== DATA_DIR) {
    throw new Error('Access denied: path is outside data directory');
  }
  return resolved;
}

function validateUploadPath(filePath) {
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(UPLOADS_DIR + path.sep) && resolved !== UPLOADS_DIR) {
    throw new Error('Access denied: path is outside upload directory');
  }
  return resolved;
}

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(MOCKUPS_DIR)) fs.mkdirSync(MOCKUPS_DIR, { recursive: true });
if (!fs.existsSync(ARCHIVED_MOCKUPS_DIR)) fs.mkdirSync(ARCHIVED_MOCKUPS_DIR, { recursive: true });

// ─── Default settings ─────────────────────────────────────────────────────────
const DEFAULT_SETTINGS = {
  printifyApiKey:       '',
  shopId:               '',
  shopName:             '',
  blueprintId:          null,
  printProviderId:      null,
  printProviderName:    '',
  defaultPrice:         2999,
  defaultCompareAtPrice: 3999,
  defaultSizes:         ['S', 'M', 'L', 'XL', '2XL'],
  setupComplete:        false,
  colorMappings:        [],
  shopifyAdminToken:    '',
  shopifyDomain:        '',
  shopifyClientId:      '',
  shopifyClientSecret:  '',
};

function sanitizeApiKey(key) {
  if (typeof key !== 'string') return '';
  let clean = key.trim();
  clean = clean.replace(/^Bearer\s+/i, '');
  clean = clean.replace(/[^A-Za-z0-9._-]/g, '');
  return clean;
}

function readSettings() {
  const file = validateDataPath(SETTINGS_FILE);
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify(DEFAULT_SETTINGS, null, 2));
    return { ...DEFAULT_SETTINGS };
  }
  try {
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

function writeSettings(data) {
  fs.writeFileSync(validateDataPath(SETTINGS_FILE), JSON.stringify(data, null, 2));
}

function readHistory() {
  const file = validateDataPath(HISTORY_FILE);
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify([], null, 2));
    return [];
  }
  try {
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch {
    return [];
  }
}

function writeHistory(data) {
  fs.writeFileSync(validateDataPath(HISTORY_FILE), JSON.stringify(data, null, 2));
}

// ─── Security headers ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  // CSP: allow self + fonts.googleapis.com for the Google Fonts in index.html
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self'; " +
    "style-src 'self' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: blob: https:; " +
    "connect-src 'self' blob:; " +
    "frame-ancestors 'none'; " +
    "object-src 'none';"
  );
  next();
});

// ─── CORS (allow local Vite dev server on 3006) ───────────────────────────────
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigins = ['http://localhost:3006', 'http://127.0.0.1:3006'];
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

app.use(express.json({ limit: '50mb' }));

// Serve Vite production build
app.use(express.static(path.join(__dirname, 'dist')));

// ─── Multer — background image upload ────────────────────────────────────────
// Security: only PNG/JPG allowed, max 10MB, UUID filename, stored outside web root
const ALLOWED_MIME_TYPES = ['image/png', 'image/jpeg'];
const ALLOWED_EXTENSIONS = ['.png', '.jpg', '.jpeg'];

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename:    (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return cb(new Error('Invalid file extension'));
    }
    cb(null, `${uuidv4()}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      return cb(new Error('Only PNG and JPG images are allowed'));
    }
    cb(null, true);
  },
});

// ─── Printify proxy helper ────────────────────────────────────────────────────
async function printifyRequest(method, path_, body, apiKey, maxRetries = 10) {
  const token = sanitizeApiKey(apiKey);
  const url = `https://api.printify.com${path_}`;
  const opts = {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'User-Agent':   'PrintFlow/1.0',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    console.log(`[Printify API Request] ${method} ${url} (Attempt ${attempt})`);
    try {
      const res  = await fetch(url, opts);
      const text = await res.text();
      let data;
      try { data = JSON.parse(text); } catch { data = { error: text }; }
      console.log(`[Printify API Response] ${method} ${url} -> Status: ${res.status}`, JSON.stringify(data).substring(0, 500));
      
      if (res.status === 429 && attempt < maxRetries) {
        const headersObj = {};
        res.headers.forEach((val, key) => { headersObj[key] = val; });
        console.log(`[Printify API Rate Limit] 429 Headers:`, JSON.stringify(headersObj));

        const retryAfterStr = res.headers.get('retry-after') || res.headers.get('Retry-After');
        let delayMs = Math.pow(2, attempt) * 2000; // 4s, 8s, 16s, 32s, 64s...
        if (retryAfterStr) {
          const seconds = parseInt(retryAfterStr, 10);
          if (!isNaN(seconds)) {
            delayMs = (seconds + 1) * 1000;
            console.log(`[Printify API Rate Limit] Respecting Retry-After header: ${retryAfterStr}s. Waiting ${delayMs}ms.`);
          }
        }
        if (delayMs > 60000) delayMs = 60000;

        console.warn(`[Printify API Rate Limit] 429 Too Many Attempts. Retrying in ${delayMs}ms...`);
        await new Promise(r => setTimeout(r, delayMs));
        continue;
      }
      
      return { status: res.status, data };
    } catch (err) {
      console.error(`[Printify API Error] ${method} ${url} ->`, err);
      if (attempt < maxRetries) {
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }
      return { status: 500, data: { error: err.message } };
    }
  }
}

// ─── Shopify GraphQL proxy helper ────────────────────────────────────────────
async function shopifyRequest(query, variables, token, domain, retries = 3) {
  const url = `https://${domain}/admin/api/2025-01/graphql.json`;
  try {
    const res  = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type':            'application/json',
        'X-Shopify-Access-Token':  token,
      },
      body: JSON.stringify({ query, variables }),
    });
    
    if (res.status === 429 && retries > 0) {
      console.log(`[Shopify GraphQL] 429 Rate Limit Hit. Retrying in 2s...`);
      await new Promise(r => setTimeout(r, 2000));
      return shopifyRequest(query, variables, token, domain, retries - 1);
    }

    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  } catch (err) {
    return { status: 500, data: { errors: [{ message: err.message }] } };
  }
}

async function shopifyRestRequest(method, path, body, token, domain, retries = 3) {
  const url = `https://${domain}/admin/api/2025-01${path}`;
  try {
    const opts = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token,
      },
    };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(url, opts);
    
    if (res.status === 429 && retries > 0) {
      console.log(`[Shopify REST] 429 Rate Limit Hit on ${path}. Retrying in 2s...`);
      await new Promise(r => setTimeout(r, 2000));
      return shopifyRestRequest(method, path, body, token, domain, retries - 1);
    }

    const data = await res.json().catch(() => ({}));
    if (!res.ok && res.status !== 429) console.error(`[Shopify REST Error]`, data);
    return { status: res.status, data };
  } catch (err) {
    console.error('[Shopify REST Exception]', err);
    return { status: 500, data: { errors: [{ message: err.message }] } };
  }
}

let cachedShopifyToken = null;
let cachedShopifyTokenExpiry = null;

async function getShopifyToken(token, domain, clientId, clientSecret) {
  if (token && token.startsWith('shpat_')) {
    return token;
  }
  if (!clientId || !clientSecret) {
    return null;
  }

  const now = Date.now();
  if (cachedShopifyToken && cachedShopifyTokenExpiry && now < cachedShopifyTokenExpiry - 60000) {
    return cachedShopifyToken;
  }

  console.log(`[Shopify OAuth] Fetching new token using Client Credentials for ${domain}`);
  try {
    const res = await fetch(`https://${domain}/admin/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'client_credentials'
      })
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error_description || errData.error || `HTTP ${res.status}`);
    }
    const data = await res.json();
    cachedShopifyToken = data.access_token;
    const expiresSeconds = data.expires_in || 86399;
    cachedShopifyTokenExpiry = now + (expiresSeconds * 1000);
    return cachedShopifyToken;
  } catch (err) {
    console.error('[Shopify OAuth Token Request Failed]', err);
    throw err;
  }
}

// (Server-side mockup saving endpoint removed in favor of client-side ZIP downloads)

// ─── Jobs ─────────────────────────────────────────────────────────────────────
function readJobs() {
  if (!fs.existsSync(JOBS_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(JOBS_FILE, 'utf8')); }
  catch { return []; }
}
function writeJobs(jobs) {
  fs.writeFileSync(JOBS_FILE, JSON.stringify(jobs, null, 2));
}

// ─── API: Settings ────────────────────────────────────────────────────────────
app.get('/api/settings', (_req, res) => {
  res.json(readSettings());
});

app.post('/api/settings', (req, res) => {
  const existing = readSettings();
  const body = { ...req.body };
  if (typeof body.printifyApiKey === 'string') {
    body.printifyApiKey = sanitizeApiKey(body.printifyApiKey);
  }
  if (typeof body.shopifyAdminToken === 'string') {
    body.shopifyAdminToken = sanitizeApiKey(body.shopifyAdminToken);
  }
  if (typeof body.shopifyDomain === 'string') {
    body.shopifyDomain = body.shopifyDomain.trim();
  }
  const updated  = { ...existing, ...body };
  writeSettings(updated);
  res.json(updated);
});

// Background image upload
app.post('/api/settings/background', (req, res) => {
  upload.single('background')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message || 'Upload failed' });
    }
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.json({ filename: req.file.filename });
  });
});

// Reset setup
app.delete('/api/settings/reset', (req, res) => {
  const settings = readSettings();
  settings.setupComplete  = false;
  settings.colorMappings  = [];
  writeSettings(settings);
  // Delete all background images
  const uploadDirResolved = path.resolve(UPLOADS_DIR);
  if (fs.existsSync(uploadDirResolved)) {
    fs.readdirSync(uploadDirResolved).forEach(f => {
      const safeFile = validateUploadPath(path.join(uploadDirResolved, f));
      fs.unlinkSync(safeFile);
    });
  }
  res.json({ ok: true });
});

// ─── API: Staging custom mockups ──────────────────────────────────────────────
app.post('/api/mockups/:id', (req, res) => {
  const id = req.params.id;
  const mockups = req.body.mockups || [];
  if (!id || !mockups.length) return res.status(400).json({ error: 'Missing id or mockups array' });
  const file = path.join(MOCKUPS_DIR, `${id}.json`);
  fs.writeFileSync(file, JSON.stringify(mockups, null, 2));

  // Archive mockups persistently
  const archivedFile = path.join(ARCHIVED_MOCKUPS_DIR, `${id}.json`);
  const archiveData = {
    timestamp: Date.now(),
    printifyProductId: id,
    mockups
  };
  fs.writeFileSync(archivedFile, JSON.stringify(archiveData, null, 2));

  res.json({ ok: true, count: mockups.length });
});

// ─── API: Jobs ────────────────────────────────────────────────────────────────
app.get('/api/jobs', (req, res) => {
  res.json({ jobs: readJobs(), serverTime: Date.now() });
});

app.post('/api/jobs/schedule', (req, res) => {
  const { printifyProductId, title } = req.body;
  if (!printifyProductId) return res.status(400).json({ error: 'Missing printifyProductId' });
  const jobs = readJobs();
  const newJob = {
    id: uuidv4(),
    printifyProductId,
    title: title || 'Scheduled Product',
    status: 'WAITING_PUBLISH', // WAITING_PUBLISH, POLLING_STATUS, WAITING_SYNC, COMPLETED, FAILED
    createdAt: Date.now(),
    lastCheckedAt: Date.now(),
    pollAttempts: 0,
    shopifyProductId: null,
  };
  jobs.push(newJob);
  writeJobs(jobs);
  res.json({ ok: true, job: newJob });
  processJobs().catch(e => console.error('[Job Runner Error on schedule]', e.message));
});

app.delete('/api/jobs/:id', async (req, res) => {
  let jobs = readJobs();
  const job = jobs.find(j => j.id === req.params.id);
  
  if (req.query.deleteFromShopify === 'true' && job && job.shopifyProductId) {
    const { shopifyAdminToken, shopifyDomain, shopifyClientId, shopifyClientSecret } = readSettings();
    if (shopifyDomain) {
      try {
        const resolvedToken = await getShopifyToken(shopifyAdminToken, shopifyDomain, shopifyClientId, shopifyClientSecret);
        if (resolvedToken) {
          await shopifyRestRequest('DELETE', `/products/${job.shopifyProductId}.json`, null, resolvedToken, shopifyDomain);
          console.log(`[Job API] Deleted product ${job.shopifyProductId} from Shopify.`);
        }
      } catch (e) {
        console.error('[Job API] Failed to delete product from Shopify:', e.message);
      }
    }
  }

  jobs = jobs.filter(j => j.id !== req.params.id);
  writeJobs(jobs);
  res.json({ ok: true });
});

app.post('/api/jobs/:id/resume', (req, res) => {
  const jobs = readJobs();
  const job = jobs.find(j => j.id === req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  if (job.status === 'NO_MOCKUPS' || job.status === 'PUBLISH_ERROR') {
    job.status = 'WAITING_PUBLISH';
    job.createdAt = 0; // force immediate check
    job.errorMessage = null;
    if (req.query.publishWithoutMockups === 'true') {
      job.publishWithoutMockups = true;
    } else {
      job.publishWithoutMockups = false;
    }
    writeJobs(jobs);
    processJobs().catch(e => console.error('[Job Runner Error on resume]', e.message));
    res.json({ success: true, job });
  } else {
    res.status(400).json({ error: 'Job is not in a resumable state' });
  }
});

// ─── API: Background images (served securely) ─────────────────────────────────
app.get('/api/backgrounds/:filename', (req, res) => {
  try {
    const safeFilename = path.basename(req.params.filename);
    const resolvedPath = validateUploadPath(path.join(UPLOADS_DIR, safeFilename));

    if (!fs.existsSync(resolvedPath)) {
      return res.status(404).json({ error: 'Not found' });
    }

    // Serve with security headers
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.sendFile(resolvedPath);
  } catch {
    return res.status(403).json({ error: 'Forbidden' });
  }
});

// ─── API: History ─────────────────────────────────────────────────────────────
app.get('/api/history', (_req, res) => {
  res.json(readHistory());
});

app.post('/api/history', (req, res) => {
  const history = readHistory();
  history.unshift(req.body);
  writeHistory(history);
  res.json({ ok: true });
});

// ─── API: Printify proxy ──────────────────────────────────────────────────────

// GET /api/printify/shops
app.get('/api/printify/shops', async (req, res) => {
  const { printifyApiKey } = readSettings();
  if (!printifyApiKey) return res.status(400).json({ error: 'API key not set' });
  const { status, data } = await printifyRequest('GET', '/v1/shops.json', null, printifyApiKey);
  res.status(status).json(data);
});

// GET /api/printify/blueprints?page=N
app.get('/api/printify/blueprints', async (req, res) => {
  const { printifyApiKey } = readSettings();
  if (!printifyApiKey) return res.status(400).json({ error: 'API key not set' });
  const page  = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const { status, data } = await printifyRequest(
    'GET', `/v1/catalog/blueprints.json?page=${page}&limit=${limit}`, null, printifyApiKey
  );
  res.status(status).json(data);
});

// GET /api/printify/blueprints/:id/providers
app.get('/api/printify/blueprints/:id/providers', async (req, res) => {
  const { printifyApiKey } = readSettings();
  if (!printifyApiKey) return res.status(400).json({ error: 'API key not set' });
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid blueprint ID' });
  const { status, data } = await printifyRequest(
    'GET', `/v1/catalog/blueprints/${id}/print_providers.json`, null, printifyApiKey
  );
  res.status(status).json(data);
});

// GET /api/printify/blueprints/:id/providers/:pid/variants
app.get('/api/printify/blueprints/:id/providers/:pid/variants', async (req, res) => {
  const { printifyApiKey } = readSettings();
  if (!printifyApiKey) return res.status(400).json({ error: 'API key not set' });
  const id  = parseInt(req.params.id);
  const pid = parseInt(req.params.pid);
  if (!id || !pid) return res.status(400).json({ error: 'Invalid IDs' });
  
  // Check cache first
  const cacheFile = validateDataPath(path.join(DATA_DIR, `variants_${id}_${pid}.json`));
  if (fs.existsSync(cacheFile)) {
    try {
      const cached = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
      console.log(`[Cache Hit] Returning variants for blueprint ${id} provider ${pid}`);
      return res.status(200).json(cached);
    } catch (e) {
      console.warn("Failed to read variants cache:", e);
    }
  }

  const { status, data } = await printifyRequest(
    'GET', `/v1/catalog/blueprints/${id}/print_providers/${pid}/variants.json`, null, printifyApiKey
  );

  // Save to cache on success
  if (status === 200 && data) {
    fs.writeFileSync(cacheFile, JSON.stringify(data, null, 2), 'utf8');
  }
  if (data && Array.isArray(data.variants)) {
    const extracted = data.variants.map(v => {
      if (v.options && typeof v.options === 'object' && !Array.isArray(v.options)) {
        return v.options.color || v.options.colors || '';
      }
      if (Array.isArray(v.options)) {
        return v.options.find(o => o.name === 'Color' || o.name === 'Colors')?.value || '';
      }
      return '';
    }).filter(Boolean);
    console.log("[Extracted color names from API response]:", Array.from(new Set(extracted)));
  } else {
    console.log("[Extracted colors] No variants array in response data", data);
  }
  res.status(status).json(data);
});

// POST /api/printify/upload-image
app.post('/api/printify/upload-image', async (req, res) => {
  try {
    const { printifyApiKey } = readSettings();
    if (!printifyApiKey) {
      return res.status(400).json({ error: 'API key not set' });
    }
    
    const { file_name, contents } = req.body;
    if (!file_name || !contents) {
      return res.status(400).json({ error: 'Missing file_name or contents' });
    }

    // CRITICAL: Strip out the data URI prefix before forwarding to Printify
    let rawBase64 = contents;
    if (rawBase64.startsWith('data:')) {
      const commaIdx = rawBase64.indexOf(',');
      if (commaIdx !== -1) {
        rawBase64 = rawBase64.substring(commaIdx + 1);
      }
    }

    const payload = {
      file_name: file_name,
      contents: rawBase64
    };

    const url = 'https://api.printify.com/v1/uploads/images.json';
    const opts = {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${printifyApiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    };

    console.log(`[Printify Upload API] Uploading ${file_name}`);
    let response = await fetch(url, opts);
    
    // Handle specific rate limits (429 errors)
    if (response.status === 429) {
      console.warn('[Printify Upload API] 429 Rate Limit Hit. Waiting 5 seconds before retrying...');
      await new Promise(resolve => setTimeout(resolve, 5000));
      response = await fetch(url, opts);
    }

    const dataText = await response.text();
    let data;
    try {
      data = JSON.parse(dataText);
    } catch {
      data = { error: dataText };
    }

    console.log(`[Printify Upload API] Response Status: ${response.status}`);
    if (!response.ok) {
        console.error(`[Printify Upload API] Error data:`, data);
    }
    res.status(response.status).json(data);
  } catch (error) {
    console.error('[Printify Upload API Error]', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/printify/products?page=N
app.get('/api/printify/products', async (req, res) => {
  const { printifyApiKey, shopId } = readSettings();
  if (!printifyApiKey || !shopId) return res.status(400).json({ error: 'API key or shop not set' });
  const page  = parseInt(req.query.page)  || 1;
  const limit = parseInt(req.query.limit) || 10;
  const { status, data } = await printifyRequest(
    'GET', `/v1/shops/${shopId}/products.json?page=${page}&limit=${limit}`, null, printifyApiKey
  );
  res.status(status).json(data);
});

// GET /api/printify/products/:id  — single product (for polling external.id)
app.get('/api/printify/products/:id', async (req, res) => {
  const { printifyApiKey, shopId } = readSettings();
  if (!printifyApiKey || !shopId) return res.status(400).json({ error: 'API key or shop not set' });
  const productId = req.params.id;
  const { status, data } = await printifyRequest(
    'GET', `/v1/shops/${shopId}/products/${productId}.json`, null, printifyApiKey
  );
  res.status(status).json(data);
});

// POST /api/printify/products
app.post('/api/printify/products', async (req, res) => {
  const { printifyApiKey, shopId } = readSettings();
  if (!printifyApiKey || !shopId) return res.status(400).json({ error: 'API key or shop not set' });
  
  // Dump payload for debugging
  fs.writeFileSync(path.join(DATA_DIR, 'last_product_payload.json'), JSON.stringify(req.body, null, 2));

  const { status, data } = await printifyRequest(
    'POST', `/v1/shops/${shopId}/products.json`, req.body, printifyApiKey
  );
  res.status(status).json(data);
});

// PUT /api/printify/products/:id
app.put('/api/printify/products/:id', async (req, res) => {
  const { printifyApiKey, shopId } = readSettings();
  if (!printifyApiKey || !shopId) return res.status(400).json({ error: 'API key or shop not set' });
  const { id } = req.params;
  const { status, data } = await printifyRequest(
    'PUT', `/v1/shops/${shopId}/products/${id}.json`, req.body, printifyApiKey
  );
  res.status(status).json(data);
});

// POST /api/printify/products/:productId/publish
app.post('/api/printify/products/:productId/publish', async (req, res) => {
  const { printifyApiKey, shopId } = readSettings();
  if (!printifyApiKey || !shopId) return res.status(400).json({ error: 'API key or shop not set' });
  const productId = req.params.productId;
  const { status, data } = await printifyRequest(
    'POST',
    `/v1/shops/${shopId}/products/${productId}/publish.json`,
    {
      title:             true,
      description:       true,
      images:            false,
      variants:          true,
      tags:              true,
      keyFeatures:       true,
      shipping_template: true,
    },
    printifyApiKey
  );
  res.status(status).json(data);
});

// POST /api/shopify/test-connection
app.post('/api/shopify/test-connection', async (req, res) => {
  const { shopifyAdminToken, shopifyDomain, shopifyClientId, shopifyClientSecret } = req.body;
  if (!shopifyDomain) {
    return res.status(400).json({ error: 'Shopify Store Domain is required' });
  }
  if (!shopifyAdminToken && (!shopifyClientId || !shopifyClientSecret)) {
    return res.status(400).json({ error: 'Either Admin API Token OR Client ID & Client Secret are required' });
  }

  const query = `
    query {
      shop {
        name
        myshopifyDomain
      }
    }
  `;

  try {
    const resolvedToken = await getShopifyToken(shopifyAdminToken, shopifyDomain, shopifyClientId, shopifyClientSecret);
    if (!resolvedToken) {
      return res.status(400).json({ error: 'Failed to resolve Shopify access token. Check credentials.' });
    }

    const { status, data } = await shopifyRequest(query, {}, resolvedToken, shopifyDomain);
    if (status === 200 && !data.errors) {
      return res.json({ success: true, shopName: data.data?.shop?.name });
    } else {
      const errMsg = data.errors?.[0]?.message || 'Invalid Shopify credentials or permissions';
      return res.status(status || 400).json({ error: errMsg, details: data });
    }
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Network error connecting to Shopify store. Check the store domain.' });
  }
});

// ─── API: Shopify — replace product images via REST API ──────────────────────

async function syncShopifyMockupsInternal(printifyProductId, shopifyProductId) {
  const { shopifyAdminToken, shopifyDomain, shopifyClientId, shopifyClientSecret } = readSettings();
  if (!shopifyDomain || (!shopifyAdminToken && (!shopifyClientId || !shopifyClientSecret))) {
    throw new Error('Shopify configuration missing.');
  }

  // Check if we have staged mockups or archived mockups
  let mockups;
  const directFile = path.join(MOCKUPS_DIR, `${printifyProductId}.json`);
  const archivedFile = path.join(ARCHIVED_MOCKUPS_DIR, `${printifyProductId}.json`);
  
  if (fs.existsSync(directFile)) {
    mockups = JSON.parse(fs.readFileSync(directFile, 'utf8'));
  } else if (fs.existsSync(archivedFile)) {
    const archiveData = JSON.parse(fs.readFileSync(archivedFile, 'utf8'));
    mockups = Array.isArray(archiveData) ? archiveData : (archiveData.mockups || []);
  } else {
    throw new Error('No staged custom mockups found for this product.');
  }

  let resolvedToken = await getShopifyToken(shopifyAdminToken, shopifyDomain, shopifyClientId, shopifyClientSecret);
  if (!resolvedToken) throw new Error('Failed to resolve Shopify credentials.');

  const productGid = `gid://shopify/Product/${shopifyProductId}`;

  // ── Step 1: Fetch existing media IDs (GraphQL) ───────────────────────────
  const queryMedia = `
    query getProductMedia($id: ID!) {
      product(id: $id) {
        id
        media(first: 50) {
          edges { node { id } }
        }
      }
    }
  `;
  const { status: s1, data: d1 } = await shopifyRequest(queryMedia, { id: productGid }, resolvedToken, shopifyDomain);
  const mediaEdges = d1?.data?.product?.media?.edges || [];
  const existingIds = mediaEdges.map(e => e.node.id);

  // ── Step 2: Fetch Shopify Variants (REST) ────────────────────────────────
  const { status: vStat, data: vData } = await shopifyRestRequest('GET', `/products/${shopifyProductId}.json`, null, resolvedToken, shopifyDomain);
  if (vStat !== 200 || !vData.product) {
    throw new Error(`Failed to fetch Shopify product variants (Status ${vStat})`);
  }
  const variants = vData.product.variants || [];
  console.log(`[sync-mockups] Shopify product has ${variants.length} variants.`);

  // ── Step 3: Delete existing Printify mockups (GraphQL) ───────────────────
  if (existingIds.length > 0) {
    const mutDelete = `
      mutation deleteMedia($productId: ID!, $mediaIds: [ID!]!) {
        productDeleteMedia(productId: $productId, mediaIds: $mediaIds) {
          deletedMediaIds
        }
      }
    `;
    await shopifyRequest(mutDelete, { productId: productGid, mediaIds: existingIds }, resolvedToken, shopifyDomain);
  }

  // ── Step 4: Upload Custom Mockups & Assign to Variants (REST) ────────────
  let successCount = 0;
  for (const m of mockups) {
    const colorNameLower = (m.colorName || '').toLowerCase().trim();
    const matchedVariantIds = variants
      .filter(v => {
        const o1 = (v.option1 || '').toLowerCase().trim();
        const o2 = (v.option2 || '').toLowerCase().trim();
        const o3 = (v.option3 || '').toLowerCase().trim();
        return o1 === colorNameLower || o2 === colorNameLower || o3 === colorNameLower;
      })
      .map(v => v.id);
    console.log(`[sync-mockups] Color "${m.colorName}" matched ${matchedVariantIds.length} Shopify variant(s)`);
    const payload = {
      image: {
        attachment: m.base64,
        filename: `mockup_${m.colorName.replace(/\s+/g, '_')}.jpg`,
        variant_ids: matchedVariantIds
      }
    };
    const { status: iStat } = await shopifyRestRequest('POST', `/products/${shopifyProductId}/images.json`, payload, resolvedToken, shopifyDomain);
    if (iStat === 201 || iStat === 200) successCount++;
    await new Promise(r => setTimeout(r, 1000));
  }

  return { deleted: existingIds.length, created: successCount };
}

// POST /api/shopify/sync-mockups
app.post('/api/shopify/sync-mockups', async (req, res) => {
  const { printifyProductId, shopifyProductId } = req.body;
  if (!printifyProductId || !shopifyProductId) {
    return res.status(400).json({ error: 'printifyProductId and shopifyProductId are required' });
  }
  try {
    const result = await syncShopifyMockupsInternal(printifyProductId, shopifyProductId);
    res.json({ ok: true, ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/shopify/sync-library-product
app.post('/api/shopify/sync-library-product', async (req, res) => {
  const { printifyProductId, shopifyProductId } = req.body;
  if (!printifyProductId || !shopifyProductId) {
    return res.status(400).json({ error: 'printifyProductId and shopifyProductId are required' });
  }
  
  const directFile = path.join(MOCKUPS_DIR, `${printifyProductId}.json`);
  const archivedFile = path.join(ARCHIVED_MOCKUPS_DIR, `${printifyProductId}.json`);

  if (!fs.existsSync(directFile) && fs.existsSync(archivedFile)) {
    try {
      const archiveData = JSON.parse(fs.readFileSync(archivedFile, 'utf8'));
      const mockups = Array.isArray(archiveData) ? archiveData : (archiveData.mockups || []);
      fs.writeFileSync(directFile, JSON.stringify(mockups, null, 2));
      console.log(`[sync-library-product] Staged mockups restored from archive for product ${printifyProductId}`);
    } catch (e) {
      console.error(`[sync-library-product] Restoring mockups failed:`, e.message);
    }
  }

  try {
    const jobs = readJobs();
    
    // Prevent duplicate active sync jobs
    const existingJob = jobs.find(j => j.printifyProductId === printifyProductId && !['COMPLETED', 'FAILED', 'NO_MOCKUPS', 'PUBLISH_ERROR'].includes(j.status));
    if (existingJob) {
      return res.status(400).json({ error: 'A sync or publish job is already active for this product' });
    }

    // Get product title for display name
    const { printifyApiKey, shopId } = readSettings();
    let title = 'Shopify Image Sync';
    try {
      const productRes = await printifyRequest('GET', `/v1/shops/${shopId}/products/${printifyProductId}.json`, null, printifyApiKey);
      if (productRes.data && productRes.data.title) {
        title = `Sync: ${productRes.data.title}`;
      }
    } catch (e) {
      // ignore
    }

    const newJob = {
      id: uuidv4(),
      printifyProductId,
      title,
      status: 'WAITING_SHOPIFY_SYNC',
      createdAt: Date.now(),
      lastCheckedAt: 0, // force immediate execution
      pollAttempts: 0,
      shopifyProductId,
    };

    jobs.push(newJob);
    writeJobs(jobs);
    
    processJobs().catch(e => console.error('[Job Runner Error on library sync]', e.message));
    res.json({ ok: true, scheduled: true, jobId: newJob.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/jobs/:id', (req, res) => {
  const jobs = readJobs();
  const job = jobs.find(j => j.id === req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json({
    ...job,
    printifyUrl: job.printifyProductId ? `https://printify.com/app/products/${job.printifyProductId}` : null
  });
});

// ─── Background Job Runner ─────────────────────────────────────────────────────
const activeJobs = new Set();
const sleep = ms => new Promise(r => setTimeout(r, ms));

let isProcessingJobs = false;

async function processJobs() {
  if (isProcessingJobs) return;
  isProcessingJobs = true;
  try {
    const jobs = readJobs();
    const now = Date.now();

    for (let job of jobs) {
      // Skip terminal states and already-running jobs
      if (['COMPLETED', 'FAILED', 'NO_MOCKUPS', 'PUBLISH_ERROR'].includes(job.status)) continue;
      if (activeJobs.has(job.id)) continue;

      // ── Phase 1: Wait 40s → check Printify auto-generated mockups → publish ──────
      if (job.status === 'WAITING_PUBLISH') {
        if (now - job.createdAt >= 40000) {
          activeJobs.add(job.id);
          (async () => {
            try {
              const { printifyApiKey, shopId } = readSettings();

              // 1a: Fetch product from Printify and check images array
              const productRes = await printifyRequest(
                'GET',
                `/v1/shops/${shopId}/products/${job.printifyProductId}.json`,
                null,
                printifyApiKey
              );
              const product = productRes.data;
              
              // Check if user manually published it (external.id exists)
              if (product?.external?.id) {
                console.log(`[Job Runner] Product ${job.printifyProductId} already published manually. Skipping publish step.`);
                const current = readJobs();
                const j = current.find(x => x.id === job.id);
                if (j) {
                  j.shopifyProductId = String(product.external.id);
                  j.status = 'WAITING_SHOPIFY_SYNC';
                  j.lastCheckedAt = Date.now();
                  writeJobs(current);
                }
                return;
              }

              const images = Array.isArray(product?.images) ? product.images : [];
              console.log(`[Job Runner] ${job.title}: ${images.length} mockup(s) found after 40s (publishWithoutMockups=${job.publishWithoutMockups})`);

              if (images.length === 0 && !job.publishWithoutMockups) {
                // Printify didn't generate any mockups — send user to Printify to upload
                console.error(`[Job Runner] NO_MOCKUPS for product ${job.printifyProductId}`);
                const current = readJobs();
                const j = current.find(x => x.id === job.id);
                if (j) {
                  j.status = 'NO_MOCKUPS';
                  j.errorMessage = 'Printify generated 0 mockups. Please upload mockups manually in Printify or publish without mockups.';
                  j.printifyUrl = `https://printify.com/app/mockup-library/shops/${shopId}/products/${job.printifyProductId}`;
                  writeJobs(current);
                }
                return;
              }

              // 1b: Publish product on Printify (triggers Printify → Shopify sync)
              console.log(`[Job Runner] Publishing ${job.title}...`);
              const publishImages = job.publishWithoutMockups ? false : true;
              const pubRes = await printifyRequest(
                'POST',
                `/v1/shops/${shopId}/products/${job.printifyProductId}/publish.json`,
                {
                  title:             true,
                  description:       true,
                  images:            publishImages,
                  variants:          true,
                  tags:              true,
                  keyFeatures:       true,
                  shipping_template: true,
                },
                printifyApiKey
              );

              if (pubRes.status !== 200) {
                throw new Error(`Publish returned HTTP ${pubRes.status}: ${JSON.stringify(pubRes.data)}`);
              }

              const current = readJobs();
              const j = current.find(x => x.id === job.id);
              if (j) {
                j.status = 'POLLING_STATUS';
                j.lastCheckedAt = Date.now();
                j.pollAttempts = 0;
                console.log(`[Job Runner] Publish triggered for ${job.title} — now polling for Shopify ID`);
                writeJobs(current);
              }
            } catch (e) {
              console.error(`[Job Runner] Phase 1 error for ${job.id}:`, e.message);
              const current = readJobs();
              const j = current.find(x => x.id === job.id);
              if (j) { j.status = 'FAILED'; j.errorMessage = e.message; writeJobs(current); }
            } finally {
              activeJobs.delete(job.id);
            }
          })();
        }
      }

      // ── Phase 2: Poll every 60s — wait for external.id (= Shopify product ID) ─────
      else if (job.status === 'POLLING_STATUS') {
        if (now - job.lastCheckedAt >= 60000) {
          activeJobs.add(job.id);
        }
      }

      // ── Phase 3: Wait 30s after publish, then replace Shopify mockups ────────────
      else if (job.status === 'WAITING_SHOPIFY_SYNC') {
        if (now - job.lastCheckedAt >= 30000) {
          activeJobs.add(job.id);
          (async () => {
            try {
              console.log(`[Job Runner] Phase 3: Syncing Shopify mockups for ${job.title}...`);
              const res = await fetch(`http://127.0.0.1:${PORT}/api/shopify/sync-mockups`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  printifyProductId: job.printifyProductId,
                  shopifyProductId: job.shopifyProductId,
                }),
              });
              const body = await res.json().catch(() => ({}));
              const current = readJobs();
              const j = current.find(x => x.id === job.id);
              if (j) {
                if (res.ok) {
                  j.status = 'COMPLETED';
                  console.log(`[Job Runner] ✓ Shopify mockups synced for ${job.title}: deleted=${body.deleted}, uploaded=${body.created}`);
                } else {
                  j.status = 'COMPLETED';
                  j.shopifySyncWarning = `Shopify mockup sync returned ${res.status}: ${JSON.stringify(body)}`;
                  console.warn(`[Job Runner] ⚠ Shopify mockup sync failed for ${job.title} (product still published):`, body);
                }
                writeJobs(current);
              }
            } catch (e) {
              console.error(`[Job Runner] Phase 3 error for ${job.id}:`, e.message);
              const current = readJobs();
              const j = current.find(x => x.id === job.id);
              if (j) {
                j.status = 'COMPLETED';
                j.shopifySyncWarning = e.message;
                writeJobs(current);
              }
            } finally {
              activeJobs.delete(job.id);
            }
          })();
        }
      }
    }

    // ── Batch polling for all due POLLING_STATUS jobs ────────────────────────────
    if (activeJobs.size > 0) {
      const current = readJobs();
      const duePollJobs = current.filter(j => activeJobs.has(j.id) && j.status === 'POLLING_STATUS');
      
      if (duePollJobs.length > 0) {
        (async () => {
          try {
            const { printifyApiKey, shopId } = readSettings();
            console.log(`[Job Runner] Batch polling ${duePollJobs.length} product(s)...`);
            
            // Fetch all products in parallel
            const results = await Promise.all(
              duePollJobs.map(job =>
                printifyRequest(
                  'GET',
                  `/v1/shops/${shopId}/products/${job.printifyProductId}.json`,
                  null,
                  printifyApiKey
                ).then(res => ({ jobId: job.id, jobTitle: job.title, product: res.data }))
                  .catch(e => ({ jobId: job.id, jobTitle: job.title, error: e.message }))
              )
            );

            // Update all jobs with results
            const updated = readJobs();
            for (const result of results) {
              const j = updated.find(x => x.id === result.jobId);
              if (!j) continue;

              j.pollAttempts = (j.pollAttempts || 0) + 1;
              j.lastCheckedAt = Date.now();

              if (result.error) {
                console.error(`[Job Runner] Batch poll error for ${result.jobTitle}:`, result.error);
                continue;
              }

              const product = result.product;
              console.log(`[Job Runner] Batch poll #${j.pollAttempts} for ${result.jobTitle}: is_locked=${product?.is_locked}, external.id=${product?.external?.id || 'none'}`);

              if (product?.external?.id) {
                j.shopifyProductId = String(product.external.id);
                j.status = 'WAITING_SHOPIFY_SYNC';
                j.lastCheckedAt = Date.now(); // reset so sync wait starts now
                console.log(`[Job Runner] ✓ Published! Shopify ID=${j.shopifyProductId} for ${result.jobTitle}`);
              } else if (product?.is_locked === false && j.pollAttempts >= 1) {
                j.status = 'PUBLISH_ERROR';
                j.errorMessage = 'Product unlocked by Printify without a Shopify ID. Likely a mockup upload issue.';
                j.printifyUrl = `https://printify.com/app/mockup-library/shops/${shopId}/products/${j.printifyProductId}`;
                console.error(`[Job Runner] PUBLISH_ERROR for ${result.jobTitle} — unlocked without external.id`);
              } else if (j.pollAttempts >= 60) {
                j.status = 'FAILED';
                j.errorMessage = 'Timed out waiting for Shopify ID after 1 hour.';
                console.error(`[Job Runner] Timeout for ${result.jobTitle}`);
              }
            }

            writeJobs(updated);

            // Clear active jobs from the running set so they can wait for the next interval
            for (const result of results) {
              activeJobs.delete(result.jobId);
            }
          } catch (e) {
            console.error(`[Job Runner] Batch polling error:`, e.message);
            for (const job of duePollJobs) {
              activeJobs.delete(job.id);
            }
          }
        })();
      }
    }
  } catch (err) {
    console.error(`[Job Runner Error]`, err);
  } finally {
    isProcessingJobs = false;
  }
}

setInterval(processJobs, 10000); // Check every 10s (10 seconds)

// ─── Mockup archival cleanup ──────────────────────────────────────────────────
// Delete staged mockup files older than 30 days to enforce retention policy.
async function cleanupOldMockups() {
  try {
    const retentionMs = 30 * 24 * 60 * 60 * 1000; // 30 days
    const now = Date.now();

    // 1. Cleanup direct MOCKUPS_DIR
    if (fs.existsSync(MOCKUPS_DIR)) {
      const files = fs.readdirSync(MOCKUPS_DIR);
      for (const f of files) {
        if (f === 'archived') continue;
        const full = path.join(MOCKUPS_DIR, f);
        try {
          const stat = fs.statSync(full);
          if (now - stat.mtimeMs > retentionMs) {
            fs.unlinkSync(full);
            console.log(`[Mockup Cleanup] Deleted old direct mockup: ${f}`);
          }
        } catch (e) {
          // ignore
        }
      }
    }

    // 2. Cleanup ARCHIVED_MOCKUPS_DIR
    if (fs.existsSync(ARCHIVED_MOCKUPS_DIR)) {
      const files = fs.readdirSync(ARCHIVED_MOCKUPS_DIR);
      for (const f of files) {
        const full = path.join(ARCHIVED_MOCKUPS_DIR, f);
        try {
          const stat = fs.statSync(full);
          if (now - stat.mtimeMs > retentionMs) {
            fs.unlinkSync(full);
            console.log(`[Mockup Cleanup] Deleted old archived mockup: ${f}`);
          }
        } catch (e) {
          // ignore
        }
      }
    }
  } catch (e) {
    console.error('[Mockup Cleanup] Failed to cleanup mockups:', e.message);
  }
}

// Run cleanup daily
setInterval(cleanupOldMockups, 24 * 60 * 60 * 1000);
// Also run on startup
cleanupOldMockups();

// React Router Catch-All (Must be right before app.listen)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

// ─── Start ─────────────────────────────────────────────────────────────────────
// Bind to localhost by default to reduce accidental exposure. Allow override via BIND_HOST env var.
const BIND_HOST = process.env.BIND_HOST || '127.0.0.1';
export const server = app.listen(PORT, BIND_HOST, () => {
  const actualPort = server.address().port;
  console.log(`PrintFlow server running on http://${BIND_HOST}:${actualPort}`);
});
