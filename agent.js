// ═══════════════════════════════════════════════════════
// ERPBI v10.0 — Node.js Backend + Güvenlik Katmanı
// AX 2012 R3 | msnodesqlv8 | Windows Auth
// Port: 3000 | API Key + JWT + Rate Limit + Kill Switch
// ═══════════════════════════════════════════════════════

const http    = require('http');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');
const sql     = require('msnodesqlv8');
const { execFile } = require('child_process');

// ═══════════════════════════════════════════════════════
// CONFIG — config.json'dan oku, yoksa default oluştur
// ═══════════════════════════════════════════════════════
const CONFIG_PATH = path.join(__dirname, 'config.json');
const DEFAULT_CONFIG = {
  sql: {
    server   : '2012_AX_DB_1',
    database : 'AX2012LIVE',
    driver   : 'SQL Server Native Client 11.0',
    auth     : 'windows',        // 'windows' | 'sql'
    user     : 'sa',
    pass     : 'Q1w2e3r4T5'
  },
  server: {
    port     : 3000,
    htmlFile : 'ERPBI_v9.html'
  },
  tunnel: {
    domain   : 'portal.erdemportal.com',
    service  : 'http://localhost:3000',
    status   : 'active'
  }
};

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
      const saved = JSON.parse(raw);
      // Deep merge: default + saved
      return {
        sql:    { ...DEFAULT_CONFIG.sql,    ...saved.sql },
        server: { ...DEFAULT_CONFIG.server, ...saved.server },
        tunnel: { ...DEFAULT_CONFIG.tunnel, ...saved.tunnel },
        d1:     saved.d1 || undefined
      };
    }
  } catch(e) { console.error('Config okuma hatası:', e.message); }
  return JSON.parse(JSON.stringify(DEFAULT_CONFIG));
}
function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), 'utf8');
}

let CONFIG = loadConfig();
if (!fs.existsSync(CONFIG_PATH)) saveConfig(CONFIG);

function buildConnStr() {
  const s = CONFIG.sql;
  if (s.auth === 'sql' && s.user) {
    return `Driver={${s.driver}};Server=${s.server};Database=${s.database};UID=${s.user};PWD=${s.pass}`;
  }
  return `Driver={${s.driver}};Server=${s.server};Database=${s.database};Trusted_Connection=Yes`;
}

let CONN = buildConnStr();

// ═══════════════════════════════════════════════════════
// GÜVENLİK AYARLARI — Uzman.work kontrol paneli
// ═══════════════════════════════════════════════════════
const SECURITY = {
  // Kill Switch — false yapınca TÜM API durur
  ACTIVE: true,

  // API Key — her istekte header'da gönderilmeli: X-ERPBI-Key
  API_KEYS: {
    'erpbi-ceo-2026-xK9mP2vL': { role: 'admin',  label: 'Ustad-Admin' },
    'erpbi-mobile-2026-qR7nW4': { role: 'reader', label: 'Mobile-CEO' },
  },

  // Kullanıcılar — Login endpoint için
  USERS: {
    'erdemiro': { pass: 'Uzman2026!', role: 'admin'  },
    'cahitc':   { pass: 'Cetin2026!', role: 'admin'  },
  },

  // JWT ayarları
  JWT_SECRET: 'erpbi-ustad-pasam-2026-erdem-holding-kX9mP2vL7nW4',
  JWT_EXPIRE: 30 * 24 * 60 * 60 * 1000, // 30 gun

  // Rate Limiting — IP başına dakikada max istek
  RATE_LIMIT: 120,
  RATE_WINDOW: 60 * 1000, // 1 dakika

  // Aktif token'lar
  tokens: {},

  // Rate limit sayaçları
  rateCounts: {},
};

// ── JWT Fonksiyonları ─────────────────────────────────
function jwtSign(payload) {
  const header  = Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
  const body    = Buffer.from(JSON.stringify({...payload, exp: Date.now() + SECURITY.JWT_EXPIRE})).toString('base64url');
  const sig     = crypto.createHmac('sha256', SECURITY.JWT_SECRET).update(header+'.'+body).digest('base64url');
  return header+'.'+body+'.'+sig;
}
function jwtVerify(token) {
  try {
    const [h, b, s] = token.split('.');
    const check = crypto.createHmac('sha256', SECURITY.JWT_SECRET).update(h+'.'+b).digest('base64url');
    if (check !== s) return null;
    const payload = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch(e) { return null; }
}

// ── Rate Limiter ──────────────────────────────────────
function checkRate(ip) {
  const now = Date.now();
  if (!SECURITY.rateCounts[ip] || now - SECURITY.rateCounts[ip].start > SECURITY.RATE_WINDOW) {
    SECURITY.rateCounts[ip] = { start: now, count: 0 };
  }
  SECURITY.rateCounts[ip].count++;
  return SECURITY.rateCounts[ip].count <= SECURITY.RATE_LIMIT;
}

// ── Auth Middleware ───────────────────────────────────
function authenticate(req) {
  // 1. API Key kontrolü
  const apiKey = req.headers['x-erpbi-key'] || '';
  if (apiKey && SECURITY.API_KEYS[apiKey]) {
    return { ok: true, user: SECURITY.API_KEYS[apiKey].label, role: SECURITY.API_KEYS[apiKey].role };
  }
  // 2. JWT Token kontrolü (Authorization: Bearer xxx)
  const auth = req.headers['authorization'] || '';
  if (auth.startsWith('Bearer ')) {
    const payload = jwtVerify(auth.slice(7));
    if (payload) return { ok: true, user: payload.user, role: payload.role };
  }
  // 3. Query param token (?token=xxx) — mobil için
  try {
    const u = new URL(req.url, 'http://localhost');
    const qt = u.searchParams.get('token');
    if (qt) {
      const payload = jwtVerify(qt);
      if (payload) return { ok: true, user: payload.user, role: payload.role };
    }
  } catch(e) {}
  return { ok: false };
}

// DataAreaId mapping — RecId (bigint) for ERP_BI views, string for native AX tables
const COMPANY_MAP = {
  'NT'   : { recid: '5637147576', code: 'nt'   },
  'YTY'  : { recid: '5637147577', code: 'yty'  },
  'NFGE' : { recid: '5637148327', code: 'nfge' },
  'ELM'  : { recid: '5637148326', code: 'elm'  },
  'KK'   : { recid: '5637146826', code: 'kk'   },
  'DAT'  : null
};

const HEADERS = {
  'Access-Control-Allow-Origin' : '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-ERPBI-Key, Authorization',
  'Content-Type'                : 'application/json; charset=utf-8'
};

function ok(res, data)  { res.writeHead(200, HEADERS); res.end(JSON.stringify(data)); }
function err(res, e)    { if (res.headersSent) return; res.writeHead(500, HEADERS); res.end(JSON.stringify({ error: String(e) })); }
function notFound(res)  { res.writeHead(404, HEADERS); res.end(JSON.stringify({ error: 'Endpoint bulunamadı' })); }

function query(q, params, cb) {
  sql.query(CONN, q, params || [], (e, rows) => {
    if (e) return cb(e);
    cb(null, rows || []);
  });
}

function companyWhere(company, alias) {
  const pfx = alias ? alias + '.' : '';
  if (!company || company === 'DAT') return '';
  const cm = COMPANY_MAP[company];
  if (!cm) return '';
  return `AND ${pfx}DATAAREAIDLEDGER = ${cm.recid}`;
}

// Native AX tablolar için (INVENTSUM, CUSTTRANS, SALESTABLE vs.) — string DATAAREAID
function companyWhereAX(company, alias) {
  const pfx = alias ? alias + '.' : '';
  if (!company || company === 'DAT') return '';
  const cm = COMPANY_MAP[company];
  if (!cm) return '';
  return `AND ${pfx}DATAAREAID = '${cm.code}'`;
}

function parseFilters(q) {
  const aylarRaw = q.aylar || '';
  let aylarList = [];
  if (aylarRaw) {
    aylarList = aylarRaw.split(',').map(s => {
      const [y, m] = s.trim().split('-');
      return { yil: parseInt(y), ay: parseInt(m) };
    }).filter(x => x.yil && x.ay);
  }
  // yil: explicit param > aylarList'in max yılı > cari yıl
  const yilFromList = aylarList.length > 0 ? Math.max(...aylarList.map(x=>x.yil)) : 0;
  const yil = parseInt(q.yil) || yilFromList || new Date().getFullYear();
  const minYil = aylarList.length > 0 ? Math.min(...aylarList.map(x=>x.yil)) : yil;
  return {
    company  : q.company   || 'DAT',
    yil,
    minYil,
    ay       : parseInt(q.ay)  || 0,
    aylarList,
    hesap    : q.hesap    || '',
    dim1     : q.dim1     || '',
    dim2     : q.dim2     || '',
    dim3     : q.dim3     || '',
    depo     : q.depo     || '',
    renk     : q.renk     || '',
    boyut    : q.boyut    || '',
    config   : q.config   || '',
    parti    : q.parti    || '',
    seri     : q.seri     || '',
    tesis    : q.tesis    || '',
    musteri  : q.musteri  || '',
    satici   : q.satici   || '',
    maddeGr  : q.maddeGr  || '',
    kdvKod   : q.kdvKod   || '',
    banka    : q.banka    || '',
    baslangic: q.baslangic|| '',
    bitis    : q.bitis    || '',
    limit    : parseInt(q.limit) || 500,
    // View eşleştirme override parametreleri (esl_<rol>_view, esl_<rol>_col)
    esl      : Object.fromEntries(
      Object.entries(q)
        .filter(([k]) => k.startsWith('esl_'))
        .map(([k,v]) => [k, v])
    )
  };
}

function ayWhere(f, alias) {
  const pfx = alias ? alias + '.' : '';
  const col = `${pfx}TRANSDATE`;

  // Çoklu dönem seçimi varsa (en verimli yol: OR ile ay/yıl çiftleri)
  if (f.aylarList && f.aylarList.length > 0) {
    const pairs = f.aylarList.map(d =>
      `(YEAR(${col}) = ${d.yil} AND MONTH(${col}) = ${d.ay})`
    ).join(' OR ');
    return `AND (${pairs})`;
  }

  // Tekli yıl+ay
  let w = `AND YEAR(${col}) = ${f.yil}`;
  if (f.ay > 0) w += ` AND MONTH(${col}) = ${f.ay}`;
  return w;
}

// ── Router ────────────────────────────────────────────────
const ROUTES = {};

function route(path, handler) { ROUTES[path] = handler; }

// ═══════════════════════════════════════════════════════
// 1. BAĞLANTI TESTİ
// ═══════════════════════════════════════════════════════
route('/api/query', (req, res, f) => { if (req.method !== 'POST') { res.writeHead(405, HEADERS); return res.end(JSON.stringify({error:'POST required'})); } let body=''; req.on('data', c => { body += c.toString(); }); req.on('end', () => { try { const data = JSON.parse(body); const q = data.query; if (!q) { res.writeHead(400, HEADERS); return res.end(JSON.stringify({error:'query required'})); } query(q, [], (e, rows) => { if (e) return err(res, e); ok(res, {data: rows}); }); } catch(e) { err(res, e); } }); });
route('/api/ping', (req, res, f) => {
  query(`SELECT TOP 1 GETDATE() AS now, @@SERVERNAME AS srv`, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { status: 'OK', server: rows[0]?.srv, time: rows[0]?.now });
  });
});

// ═══════════════════════════════════════════════════════
// 2. GELİR TABLOSU
// ═══════════════════════════════════════════════════════
route('/api/gelir', (req, res, f) => {
  const cw = companyWhere(f.company);
  const aw = ayWhere(f);
  const hesapFilter = f.hesap ? `AND MAINACCOUNTNUM LIKE '${f.hesap}%'` : '';
  const dim1Filter  = f.dim1  ? `AND DIMENSION = '${f.dim1}'` : '';

  // View eşleştirme override
  const esl = f.esl || {};
  const tarihCol  = esl.esl_tarih_col  || 'TRANSDATE';
  const tutarCol  = esl.esl_tutar_col  || 'AMOUNTMST';
  const hesapCol  = esl.esl_hesap_col  || 'MAINACCOUNTNUM';
  const sirketCol = esl.esl_sirket_col || 'DATAAREAIDLEDGER';
  const tablo     = esl.esl_tarih_view || 'ERP_BI_LEDGERTRANS';

  const q = `
    SELECT
      MONTH(${tarihCol}) AS ay,
      LEFT(${hesapCol}, 10) AS MAINACCOUNTNUM,
      SUM(${tutarCol}) * -1 AS tutar
    FROM ${tablo}
    WHERE LEFT(${hesapCol}, 10) BETWEEN '600' AND '629'
      ${cw} ${aw} ${hesapFilter} ${dim1Filter}
    GROUP BY MONTH(${tarihCol}), LEFT(${hesapCol}, 10)
    ORDER BY ay, ${hesapCol}`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    // Gruplama: 60x = gelir, 62x = smm
    const aylik = {};
    rows.forEach(r => {
      const m = r.ay;
      if (!aylik[m]) aylik[m] = { ay: m, gelir: 0, smm: 0 };
      const tutar = parseFloat(r.tutar) || 0;
      if ((r.MAINACCOUNTNUM||'').substring(0,10).startsWith('60')) aylik[m].gelir += tutar;
      if ((r.MAINACCOUNTNUM||'').substring(0,10).startsWith('62')) aylik[m].smm   += tutar;
    });
    const list = Object.values(aylik).map(x => ({
      ...x,
      brutKar: x.gelir - x.smm,
      brutMarj: x.gelir > 0 ? ((x.gelir - x.smm) / x.gelir * 100).toFixed(2) : 0
    }));
    ok(res, { rows: list });
  });
});

// ═══════════════════════════════════════════════════════
// 3. KÂR / ZARAR
// ═══════════════════════════════════════════════════════
route('/api/karZarar', (req, res, f) => {
  const cw = companyWhere(f.company);
  const aw = ayWhere(f);

  const q = `
    SELECT
      L.MAINACCOUNTNUM,
      H.ACCOUNTNAME,
      SUM(L.AMOUNTMST) AS tutar_raw
    FROM ERP_BI_LEDGERTRANS L
    LEFT JOIN ERP_BI_HESAPPLANI H ON H.MAINACCOUNTID = L.MAINACCOUNTNUM
    WHERE LEFT(L.MAINACCOUNTNUM, 10) BETWEEN '600' AND '699'
      ${cw} ${aw}
    GROUP BY L.MAINACCOUNTNUM, H.ACCOUNTNAME
    ORDER BY L.MAINACCOUNTNUM`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    const data = rows.map(r => {
      const acc = r.MAINACCOUNTNUM;
      const raw = parseFloat(r.tutar_raw) || 0;
      // Gelir hesapları AX'te negatif → pozitife çevir
      const acc10 = (r.MAINACCOUNTNUM||'').substring(0,10);
      const tutar = acc10 < '620' ? raw * -1 : raw;
      return { hesap: acc, isim: r.ACCOUNTNAME || '', tutar };
    });
    ok(res, { rows: data });
  });
});

// ═══════════════════════════════════════════════════════
// 4. EBITDA
// ═══════════════════════════════════════════════════════
route('/api/ebitda', (req, res, f) => {
  const cw = companyWhere(f.company);
  const aw = ayWhere(f);

  const q = `
    SELECT
      MONTH(TRANSDATE) AS ay,
      MAINACCOUNTNUM,
      SUM(AMOUNTMST) AS tutar_raw
    FROM ERP_BI_LEDGERTRANS
    WHERE (
      LEFT(MAINACCOUNTNUM,10) BETWEEN '600' AND '699'
      OR LEFT(MAINACCOUNTNUM,10) BETWEEN '730' AND '739'
      OR LEFT(MAINACCOUNTNUM,10) BETWEEN '770' AND '779'
    )
    ${cw} ${aw}
    GROUP BY MONTH(TRANSDATE), MAINACCOUNTNUM
    ORDER BY ay`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    const aylik = {};
    rows.forEach(r => {
      const m = r.ay;
      if (!aylik[m]) aylik[m] = { ay: m, gelir: 0, smm: 0, faalGider: 0, amortisman: 0 };
      const acc = (r.MAINACCOUNTNUM||'').substring(0,10);
      const raw = parseFloat(r.tutar_raw) || 0;
      if (acc >= '600' && acc < '620') aylik[m].gelir    += (raw * -1);
      // SMM (62x)
      else if (acc >= '620' && acc < '630') aylik[m].smm += raw;
      // Faaliyet giderleri (63x-69x)
      else if (acc >= '630' && acc < '700') {
        // Amortisman ve itfa (770-779) ayrı tut
        if (acc >= '770' && acc < '780') aylik[m].amortisman += Math.abs(raw);
        else aylik[m].faalGider += Math.abs(raw);
      }
      // 730-739 amortisman giderleri
      if (acc >= '730' && acc < '740') aylik[m].amortisman += Math.abs(raw);
    });
    const list = Object.values(aylik).map(x => {
      const brutKar   = x.gelir - x.smm;
      const faalKar   = brutKar - x.faalGider;
      const ebitda    = faalKar + x.amortisman;
      return { ...x, brutKar, faalKar, ebitda };
    });
    ok(res, { rows: list });
  });
});

// ═══════════════════════════════════════════════════════
// 5. MİZAN
// ═══════════════════════════════════════════════════════
route('/api/mizan', (req, res, f) => {
  const cw = companyWhere(f.company);
  const aw = ayWhere(f);
  const hesapFilter = f.hesap ? `AND L.MAINACCOUNTNUM LIKE '${f.hesap}%'` : '';
  const dim2Filter  = f.dim2  ? `AND L.DIMENSION2_ = '${f.dim2}'` : '';

  const q = `
    SELECT
      L.MAINACCOUNTNUM,
      H.ACCOUNTNAME,
      H.ACCOUNTPLTYPE,
      SUM(CASE WHEN L.AMOUNTMST > 0 THEN  L.AMOUNTMST ELSE 0 END) AS borc,
      SUM(CASE WHEN L.AMOUNTMST < 0 THEN -L.AMOUNTMST ELSE 0 END) AS alacak,
      SUM(L.AMOUNTMST) AS bakiye
    FROM ERP_BI_LEDGERTRANS L
    LEFT JOIN ERP_BI_HESAPPLANI H ON H.MAINACCOUNTID = L.MAINACCOUNTNUM
    WHERE 1=1
      ${cw} ${aw} ${hesapFilter} ${dim2Filter}
    GROUP BY LEFT(L.MAINACCOUNTNUM,10), H.ACCOUNTNAME, H.ACCOUNTPLTYPE
    ORDER BY L.MAINACCOUNTNUM`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap  : r.MAINACCOUNTNUM,
      isim   : r.ACCOUNTNAME || '',
      tip    : r.ACCOUNTPLTYPE || '',
      borc   : parseFloat(r.borc)   || 0,
      alacak : parseFloat(r.alacak) || 0,
      bakiye : parseFloat(r.bakiye) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 6. DÖNEM TABLOSU
// ═══════════════════════════════════════════════════════
route('/api/donem', (req, res, f) => {
  const cw = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const q = `
    SELECT DISTINCT YIL, AY, AYADI, CEYREK, CEYREKADI
    FROM ERP_BI_DONEM
    WHERE YIL >= YEAR(GETDATE()) - 5
      AND YIL <= YEAR(GETDATE()) + 1
      ${cw}
    ORDER BY YIL DESC, AY`;
  query(q, [], (e, rows) => {
    if (e) {
      // Hata durumunda cari yılı manuel olarak döndür
      const yil = new Date().getFullYear();
      const ayAdi = ['Oca','Şub','Mar','Nis','May','Haz','Tem','Ağu','Eyl','Eki','Kas','Ara'];
      const ceyrek = ['Q1','Q1','Q1','Q2','Q2','Q2','Q3','Q3','Q3','Q4','Q4','Q4'];
      const ceyrekAdi = ['1. Çeyrek','1. Çeyrek','1. Çeyrek','2. Çeyrek','2. Çeyrek','2. Çeyrek','3. Çeyrek','3. Çeyrek','3. Çeyrek','4. Çeyrek','4. Çeyrek','4. Çeyrek'];
      const fallback = [];
      for (let y = yil; y >= yil - 2; y--) {
        for (let m = 12; m >= 1; m--) {
          fallback.push({ YIL: y, AY: m, AYADI: ayAdi[m-1]+' '+y, CEYREK: ceyrek[m-1], CEYREKADI: ceyrekAdi[m-1] });
        }
      }
      return ok(res, { rows: fallback, fallback: true });
    }
    if (!rows || rows.length === 0) {
      // Veri yoksa manuel üret
      const yil = new Date().getFullYear();
      const ayAdi = ['Oca','Şub','Mar','Nis','May','Haz','Tem','Ağu','Eyl','Eki','Kas','Ara'];
      const ceyrek = ['Q1','Q1','Q1','Q2','Q2','Q2','Q3','Q3','Q3','Q4','Q4','Q4'];
      const ceyrekAdi = ['1. Çeyrek','1. Çeyrek','1. Çeyrek','2. Çeyrek','2. Çeyrek','2. Çeyrek','3. Çeyrek','3. Çeyrek','3. Çeyrek','4. Çeyrek','4. Çeyrek','4. Çeyrek'];
      const fallback = [];
      for (let y = yil; y >= yil - 2; y--) {
        for (let m = 12; m >= 1; m--) {
          fallback.push({ YIL: y, AY: m, AYADI: ayAdi[m-1]+' '+y, CEYREK: ceyrek[m-1], CEYREKADI: ceyrekAdi[m-1] });
        }
      }
      return ok(res, { rows: fallback, fallback: true });
    }
    ok(res, { rows });
  });
});

// ═══════════════════════════════════════════════════════
// 7. HESAP PLANI
// ═══════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════
// MÜŞTERİ KARTLARI — ERP_BI_MUSTERIKARTI
// ═══════════════════════════════════════════════════════
route('/api/musteri', (req, res, f) => {
  const cw     = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const search = f.arama ? `AND (CUSTACCOUNT LIKE '%${f.arama}%' OR CUSTNAME LIKE '%${f.arama}%')` : '';

  const q = `
    SELECT TOP ${f.limit}
      CUSTACCOUNT, CUSTNAME, CUSTGROUPID, CUSTGROUPNAME,
      CURRENCY, PAYMTERMID, DIMENSION, DATAAREAID
    FROM ERP_BI_MUSTERIKARTI
    WHERE 1=1 ${cw} ${search}
    ORDER BY CUSTACCOUNT`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap : r.CUSTACCOUNT  || '',
      isim  : r.CUSTNAME     || '',
      grup  : r.CUSTGROUPID  || '',
      grpAd : r.CUSTGROUPNAME|| '',
      doviz : r.CURRENCY     || '',
      vade  : r.PAYMTERMID   || '',
      dim1  : r.DIMENSION    || ''
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// SATICI KARTLARI — ERP_BI_SATICIKARTI
// ═══════════════════════════════════════════════════════
route('/api/satici', (req, res, f) => {
  const cw     = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const search = f.arama ? `AND (VENDACCOUNT LIKE '%${f.arama}%' OR VENDNAME LIKE '%${f.arama}%')` : '';

  const q = `
    SELECT TOP ${f.limit}
      VENDACCOUNT, VENDNAME, VENDGROUPID, VENDGROUPNAME,
      CURRENCY, PAYMTERMID, DIMENSION, DATAAREAID
    FROM ERP_BI_SATICIKARTI
    WHERE 1=1 ${cw} ${search}
    ORDER BY VENDACCOUNT`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap : r.VENDACCOUNT  || '',
      isim  : r.VENDNAME     || '',
      grup  : r.VENDGROUPID  || '',
      grpAd : r.VENDGROUPNAME|| '',
      doviz : r.CURRENCY     || '',
      vade  : r.PAYMTERMID   || '',
      dim1  : r.DIMENSION    || ''
    }))});
  });
});

route('/api/hesapPlani', (req, res, f) => {
  const cw        = f.company && f.company !== 'DAT' ? `AND MAINACCOUNTID IS NOT NULL` : '';
  const tipFilter = f.hesap ? `AND MAINACCOUNTID LIKE '${f.hesap}%'` : '';
  const q = `SELECT MAINACCOUNTID, ACCOUNTNAME, ACCOUNTPLTYPE FROM ERP_BI_HESAPPLANI WHERE 1=1 ${tipFilter} ORDER BY MAINACCOUNTID`;
  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows });
  });
});

// ═══════════════════════════════════════════════════════
// 8. SATIŞ ANALİZİ — ERP_BI_SATISFATURA
// ═══════════════════════════════════════════════════════
route('/api/satis', (req, res, f) => {
  const cw = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(INVOICEDATE)=${d.yil} AND MONTH(INVOICEDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(INVOICEDATE) = ${f.yil}`;
  const musteriFilter = f.musteri ? `AND INVOICEACCOUNT = '${f.musteri}'` : '';
  const dimFilter     = f.dim1    ? `AND DIMENSION = '${f.dim1}'`         : '';

  const q = `
    SELECT
      MONTH(INVOICEDATE)            AS ay,
      YEAR(INVOICEDATE)             AS yil,
      INVOICEACCOUNT                AS musteriKodu,
      NAME                          AS musteriAdi,
      SUM(LINEAMOUNTMST)            AS ciro,
      SUM(QTY)                      AS miktar,
      COUNT(DISTINCT INVOICEID)     AS faturaAdedi
    FROM ERP_BI_SATISFATURA
    WHERE INVOICEDATE IS NOT NULL
      ${cw} ${aw} ${musteriFilter} ${dimFilter}
    GROUP BY MONTH(INVOICEDATE), YEAR(INVOICEDATE), INVOICEACCOUNT, NAME
    ORDER BY yil, ay, ciro DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      ay       : r.ay,
      yil      : r.yil,
      musteri  : r.musteriKodu || '',
      isim     : r.musteriAdi  || '',
      ciro     : parseFloat(r.ciro)   || 0,
      miktar   : parseFloat(r.miktar) || 0,
      fatura   : parseInt(r.faturaAdedi) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 9. ALACAK YAŞLANDIRMAanswer
// ═══════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════
// 9. ALACAK YAŞLANDIRMA — ERP_BI_ALACAK
// ═══════════════════════════════════════════════════════
route('/api/alacak', (req, res, f) => {
  const cw          = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const musteriFilter = f.musteri ? `AND ACCOUNTNUM = '${f.musteri}'` : '';
  const grupFilter    = f.musteriGr ? `AND CUSTGROUP = '${f.musteriGr}'` : '';
  const aw          = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(TRANSDATE)=${d.yil} AND MONTH(TRANSDATE)=${d.ay})`).join(' OR ')})`
    : '';

  const q = `
    SELECT
      ACCOUNTNUM,
      CUSTNAME,
      CUSTGROUP,
      TRANSDATE,
      DUEDATE,
      AMOUNTMST,
      OPENAMOUNTMST,
      AGINGDAYS,
      CASE
        WHEN AGINGDAYS BETWEEN 0  AND 30  THEN '0-30'
        WHEN AGINGDAYS BETWEEN 31 AND 60  THEN '31-60'
        WHEN AGINGDAYS BETWEEN 61 AND 90  THEN '61-90'
        ELSE '90+'
      END AS bant
    FROM ERP_BI_ALACAK
    WHERE (CLOSED IS NULL OR CLOSED <= '1900-01-02')
      AND OPENAMOUNTMST <> 0
      ${cw} ${aw} ${musteriFilter} ${grupFilter}
    ORDER BY AGINGDAYS DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap  : r.ACCOUNTNUM,
      isim   : r.CUSTNAME   || '',
      grup   : r.CUSTGROUP  || '',
      tarih  : r.TRANSDATE,
      vade   : r.DUEDATE,
      tutar  : parseFloat(r.AMOUNTMST)     || 0,
      bakiye : Math.abs(parseFloat(r.OPENAMOUNTMST) || 0),
      gun    : parseInt(r.AGINGDAYS)       || 0,
      bant   : r.bant
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 10. BORÇ YAŞLANDIRMA — ERP_BI_BORC
// ═══════════════════════════════════════════════════════
route('/api/borc', (req, res, f) => {
  const cw        = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const saticiFilter = f.satici ? `AND ACCOUNTNUM = '${f.satici}'` : '';
  const aw        = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(TRANSDATE)=${d.yil} AND MONTH(TRANSDATE)=${d.ay})`).join(' OR ')})`
    : '';

  const q = `
    SELECT
      ACCOUNTNUM,
      VENDNAME,
      VENDGROUP,
      TRANSDATE,
      DUEDATE,
      AMOUNTMST,
      OPENAMOUNTMST,
      AGINGDAYS,
      CASE
        WHEN AGINGDAYS BETWEEN 0  AND 30  THEN '0-30'
        WHEN AGINGDAYS BETWEEN 31 AND 60  THEN '31-60'
        WHEN AGINGDAYS BETWEEN 61 AND 90  THEN '61-90'
        ELSE '90+'
      END AS bant
    FROM ERP_BI_BORC
    WHERE (CLOSED IS NULL OR CLOSED <= '1900-01-02')
      AND OPENAMOUNTMST <> 0
      ${cw} ${aw} ${saticiFilter}
    ORDER BY AGINGDAYS DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap  : r.ACCOUNTNUM,
      isim   : r.VENDNAME   || '',
      grup   : r.VENDGROUP  || '',
      tarih  : r.TRANSDATE,
      vade   : r.DUEDATE,
      tutar  : parseFloat(r.AMOUNTMST)     || 0,
      bakiye : Math.abs(parseFloat(r.OPENAMOUNTMST) || 0),
      gun    : parseInt(r.AGINGDAYS)       || 0,
      bant   : r.bant
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 11. NAKİT AKIŞI — ERP_BI_BANKA
// ═══════════════════════════════════════════════════════
route('/api/nakit', (req, res, f) => {
  const cw         = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const bankaFilter = f.banka ? `AND ACCOUNTID = '${f.banka}'` : '';
  const aw          = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(TRANSDATE)=${d.yil} AND MONTH(TRANSDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(TRANSDATE) = ${f.yil}`;

  const q = `
    SELECT
      MONTH(TRANSDATE)  AS ay,
      YEAR(TRANSDATE)   AS yil,
      ACCOUNTID,
      BANKNAME,
      SUM(CASE WHEN AMOUNTMST > 0 THEN  AMOUNTMST ELSE 0 END) AS giris,
      SUM(CASE WHEN AMOUNTMST < 0 THEN -AMOUNTMST ELSE 0 END) AS cikis,
      SUM(AMOUNTMST)                                           AS net
    FROM ERP_BI_BANKA
    WHERE TRANSDATE IS NOT NULL
      AND CANCEL = 0
      ${cw} ${aw} ${bankaFilter}
    GROUP BY MONTH(TRANSDATE), YEAR(TRANSDATE), ACCOUNTID, BANKNAME
    ORDER BY yil, ay, ACCOUNTID`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      ay     : r.ay,
      yil    : r.yil,
      hesap  : r.ACCOUNTID || '',
      banka  : r.BANKNAME  || '',
      giris  : parseFloat(r.giris) || 0,
      cikis  : parseFloat(r.cikis) || 0,
      net    : parseFloat(r.net)   || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 11b. BANKA HESAPLARI — ERP_BI_BANKA + ERP_BI_BANKAKARTI
// ═══════════════════════════════════════════════════════
route('/api/banka', (req, res, f) => {
  const cw = f.company && f.company !== 'DAT' ? `AND B.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(B.TRANSDATE)=${d.yil} AND MONTH(B.TRANSDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(B.TRANSDATE) = ${f.yil}`;

  const q = `
    SELECT
      B.ACCOUNTID,
      K.NAME          AS bankaAdi,
      K.BANKGROUPID,
      K.CURRENCYCODE  AS paraBirimi,
      K.IBAN,
      MONTH(B.TRANSDATE) AS ay,
      SUM(CASE WHEN B.AMOUNTMST > 0 THEN  B.AMOUNTMST ELSE 0 END) AS giris,
      SUM(CASE WHEN B.AMOUNTMST < 0 THEN -B.AMOUNTMST ELSE 0 END) AS cikis,
      SUM(B.AMOUNTMST)                                              AS net,
      COUNT(CASE WHEN B.RECONCILED = 0 THEN 1 END)                 AS mutabakatsiz
    FROM ERP_BI_BANKA B
    LEFT JOIN ERP_BI_BANKAKARTI K ON K.ACCOUNTID = B.ACCOUNTID
      AND K.DATAAREAID = B.DATAAREAID
    WHERE B.TRANSDATE IS NOT NULL
      AND B.CANCEL = 0
      ${cw} ${aw}
    GROUP BY B.ACCOUNTID, K.NAME, K.BANKGROUPID, K.CURRENCYCODE, K.IBAN, MONTH(B.TRANSDATE)
    ORDER BY B.ACCOUNTID, ay`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap        : r.ACCOUNTID   || '',
      banka        : r.bankaAdi    || '',
      grup         : r.BANKGROUPID || '',
      paraBirimi   : r.paraBirimi  || '',
      iban         : r.IBAN        || '',
      ay           : r.ay,
      giris        : parseFloat(r.giris)  || 0,
      cikis        : parseFloat(r.cikis)  || 0,
      net          : parseFloat(r.net)    || 0,
      mutabakatsiz : parseInt(r.mutabakatsiz) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 12. STOK BAKİYE — ERP_BI_INVENTTRANS + ERP_BI_MADDEKARTI
// ═══════════════════════════════════════════════════════
route('/api/stok', (req, res, f) => {
  const cw          = f.company && f.company !== 'DAT' ? `AND T.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const tesisFilter = f.tesis   ? `AND T.INVENTSITEID     = '${f.tesis}'`         : '';
  const depoFilter  = f.depo    ? `AND T.INVENTLOCATIONID = '${f.depo}'`          : '';
  const renkFilter  = f.renk    ? `AND T.INVENTCOLORID    = '${f.renk}'`          : '';
  const boyutFilter = f.boyut   ? `AND T.INVENTSIZEID     = '${f.boyut}'`         : '';
  const cfgFilter   = f.config  ? `AND T.CONFIGID         = '${f.config}'`        : '';
  const grpFilter   = f.maddeGr ? `AND M.ITEMGROUPID      = '${f.maddeGr}'`       : '';
  const partiFilter = f.parti   ? `AND T.INVENTBATCHID    LIKE '%${f.parti}%'`    : '';
  const seriFilter  = f.seri    ? `AND T.INVENTSERIALID   LIKE '%${f.seri}%'`     : '';

  const q = `
    SELECT TOP ${f.limit}
      T.ITEMID,
      M.ITEMNAME,
      M.ITEMGROUPID,
      T.INVENTSITEID      AS tesis,
      T.INVENTLOCATIONID  AS depo,
      T.INVENTCOLORID     AS renk,
      T.INVENTSIZEID      AS ebat,
      T.CONFIGID          AS config,
      T.INVENTBATCHID     AS parti,
      T.INVENTSERIALID    AS seri,
      SUM(T.QTY)              AS miktar,
      SUM(T.COSTAMOUNTPOSTED) AS deger
    FROM ERP_BI_INVENTTRANS T
    LEFT JOIN ERP_BI_MADDEKARTI M ON M.ITEMID = T.ITEMID AND M.DATAAREAID = T.DATAAREAID
    WHERE 1=1
      ${cw} ${tesisFilter} ${depoFilter} ${renkFilter} ${boyutFilter}
      ${cfgFilter} ${grpFilter} ${partiFilter} ${seriFilter}
    GROUP BY T.ITEMID, M.ITEMNAME, M.ITEMGROUPID,
             T.INVENTSITEID, T.INVENTLOCATIONID, T.INVENTCOLORID,
             T.INVENTSIZEID, T.CONFIGID, T.INVENTBATCHID, T.INVENTSERIALID
    HAVING SUM(T.QTY) <> 0
    ORDER BY T.ITEMID, T.INVENTLOCATIONID`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      itemId : r.ITEMID       || '',
      isim   : r.ITEMNAME     || '',
      grup   : r.ITEMGROUPID  || '',
      tesis  : r.tesis        || '',
      depo   : r.depo         || '',
      renk   : r.renk         || '',
      ebat   : r.ebat         || '',
      config : r.config       || '',
      parti  : r.parti        || '',
      seri   : r.seri         || '',
      miktar : parseFloat(r.miktar) || 0,
      deger  : parseFloat(r.deger)  || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 13. STOK YAŞLANDIRMA — ERP_BI_INVENTTRANS
// ═══════════════════════════════════════════════════════
route('/api/stokYas', (req, res, f) => {
  const cw          = f.company && f.company !== 'DAT' ? `AND T.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const tesisFilter = f.tesis   ? `AND T.INVENTSITEID     = '${f.tesis}'`        : '';
  const depoFilter  = f.depo    ? `AND T.INVENTLOCATIONID = '${f.depo}'`         : '';
  const grpFilter   = f.maddeGr ? `AND M.ITEMGROUPID      = '${f.maddeGr}'`      : '';
  const partiFilter = f.parti   ? `AND T.INVENTBATCHID    LIKE '%${f.parti}%'`   : '';
  const seriFilter  = f.seri    ? `AND T.INVENTSERIALID   LIKE '%${f.seri}%'`    : '';

  const q = `
    SELECT TOP ${f.limit}
      T.ITEMID,
      M.ITEMNAME,
      M.ITEMGROUPID,
      T.INVENTSITEID      AS tesis,
      T.INVENTLOCATIONID  AS depo,
      T.INVENTBATCHID     AS parti,
      T.INVENTSERIALID    AS seri,
      MAX(T.DATEPHYSICAL)                            AS sonHareket,
      DATEDIFF(DAY, MAX(T.DATEPHYSICAL), GETDATE())  AS sonHareketGun,
      SUM(T.QTY)              AS miktar,
      SUM(T.COSTAMOUNTPOSTED) AS deger,
      CASE
        WHEN DATEDIFF(DAY, MAX(T.DATEPHYSICAL), GETDATE()) BETWEEN 0  AND 30  THEN '0-30'
        WHEN DATEDIFF(DAY, MAX(T.DATEPHYSICAL), GETDATE()) BETWEEN 31 AND 60  THEN '31-60'
        WHEN DATEDIFF(DAY, MAX(T.DATEPHYSICAL), GETDATE()) BETWEEN 61 AND 90  THEN '61-90'
        ELSE '90+'
      END AS bant
    FROM ERP_BI_INVENTTRANS T
    LEFT JOIN ERP_BI_MADDEKARTI M ON M.ITEMID = T.ITEMID AND M.DATAAREAID = T.DATAAREAID
    WHERE T.DATEPHYSICAL IS NOT NULL
      ${cw} ${tesisFilter} ${depoFilter} ${grpFilter} ${partiFilter} ${seriFilter}
    GROUP BY T.ITEMID, M.ITEMNAME, M.ITEMGROUPID,
             T.INVENTSITEID, T.INVENTLOCATIONID, T.INVENTBATCHID, T.INVENTSERIALID
    HAVING SUM(T.QTY) > 0
    ORDER BY sonHareketGun DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      itemId : r.ITEMID      || '',
      isim   : r.ITEMNAME    || '',
      grup   : r.ITEMGROUPID || '',
      tesis  : r.tesis  || '',
      depo   : r.depo   || '',
      parti  : r.parti  || '',
      seri   : r.seri   || '',
      gun    : parseInt(r.sonHareketGun) || 0,
      bant   : r.bant,
      miktar : parseFloat(r.miktar) || 0,
      deger  : parseFloat(r.deger)  || 0
    }))});
  });
});


// ═══════════════════════════════════════════════════════
// 14. ÜRETİM EMİRLERİ — ERP_BI_URETIMEMRI
// ═══════════════════════════════════════════════════════
route('/api/uretim', (req, res, f) => {
  const cw          = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const statusFilter = f.dim1    ? `AND PRODSTATUS = ${parseInt(f.dim1)||0}` : '';
  const grpFilter    = f.maddeGr ? `AND PRODGROUPID = '${f.maddeGr}'`        : '';
  const tesisFilter  = f.tesis   ? `AND INVENTSITEID = '${f.tesis}'`         : '';
  const depoFilter   = f.depo    ? `AND INVENTLOCATIONID = '${f.depo}'`      : '';

  const q = `
    SELECT TOP ${f.limit}
      PRODID,
      ITEMID,
      ITEMNAME,
      PRODGROUPID,
      PRODSTATUS,
      QTYCALC,
      PRODUCEDQTY,
      DLVDATE,
      SCHEDDATE,
      FINISHEDDATE,
      INVENTSITEID,
      INVENTLOCATIONID,
      DATEDIFF(DAY, DLVDATE, GETDATE()) AS gecikmeGun
    FROM ERP_BI_URETIMEMRI
    WHERE PRODSTATUS NOT IN (5, 8)
      ${cw} ${statusFilter} ${grpFilter} ${tesisFilter} ${depoFilter}
    ORDER BY gecikmeGun DESC, DLVDATE`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      prodId    : r.PRODID,
      itemId    : r.ITEMID,
      isim      : r.ITEMNAME         || '',
      grupId    : r.PRODGROUPID      || '',
      status    : r.PRODSTATUS,
      planlanan : parseFloat(r.QTYCALC)     || 0,
      uretilen  : parseFloat(r.PRODUCEDQTY) || 0,
      teslim    : r.DLVDATE,
      tesis     : r.INVENTSITEID     || '',
      depo      : r.INVENTLOCATIONID || '',
      gecikme   : parseInt(r.gecikmeGun) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 15. KDV — ERP_BI_KDV
// ═══════════════════════════════════════════════════════
route('/api/kdv', (req, res, f) => {
  const cw        = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const tipFilter = f.kdvKod ? `AND TAXGROUP = '${f.kdvKod}'`  : '';
  const aw        = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(INVOICEDATE)=${d.yil} AND MONTH(INVOICEDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(INVOICEDATE) = ${f.yil}`;

  const q = `
    SELECT
      KDVTYPE,
      MONTH(INVOICEDATE)      AS ay,
      YEAR(INVOICEDATE)       AS yil,
      TAXGROUP,
      TAXITEMGROUP,
      SUM(LINEAMOUNTMST)      AS matrah,
      SUM(TAXAMOUNTMST)       AS kdv,
      SUM(QTY)                AS miktar
    FROM ERP_BI_KDV
    WHERE INVOICEDATE IS NOT NULL
      ${cw} ${aw} ${tipFilter}
    GROUP BY KDVTYPE, MONTH(INVOICEDATE), YEAR(INVOICEDATE), TAXGROUP, TAXITEMGROUP
    ORDER BY yil, ay, KDVTYPE`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      yon    : r.KDVTYPE    || '',   // 'S'=Satış, 'P'=Alış
      ay     : r.ay,
      yil    : r.yil,
      kod    : r.TAXGROUP   || '',
      kdv    : parseFloat(r.kdv)    || 0,
      matrah : parseFloat(r.matrah) || 0,
      miktar : parseFloat(r.miktar) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 16. BÜTÇE vs FİİLİ — ERP_BI_BUTCE_MUHASEBE + ERP_BI_LEDGERTRANS
// ═══════════════════════════════════════════════════════
route('/api/butce', (req, res, f) => {
  const cw  = companyWhere(f.company);
  const cwS = f.company && f.company !== 'DAT' ? `AND DATAAREAID1 = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw  = ayWhere(f);
  const awB = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(STARTDATE)=${d.yil} AND MONTH(STARTDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(STARTDATE) = ${f.yil}`;
  const dim3Filter = f.dim3 ? `AND DIMENSION3_ = '${f.dim3}'` : '';
  const hesapFilter = f.hesap ? `AND ACCOUNTNUM LIKE '${f.hesap}%'` : '';

  const qButce = `
    SELECT
      MONTH(STARTDATE) AS ay,
      YEAR(STARTDATE)  AS yil,
      ACCOUNTNUM,
      MODELNUM,
      SUM(AMOUNTMST)   AS butce
    FROM ERP_BI_BUTCE_MUHASEBE
    WHERE STARTDATE IS NOT NULL
      ${cwS} ${awB} ${dim3Filter} ${hesapFilter}
    GROUP BY MONTH(STARTDATE), YEAR(STARTDATE), ACCOUNTNUM, MODELNUM
    ORDER BY yil, ay, ACCOUNTNUM`;

  const qFiili = `
    SELECT
      MONTH(TRANSDATE) AS ay,
      YEAR(TRANSDATE)  AS yil,
      MAINACCOUNTNUM,
      SUM(AMOUNTMST)   AS fiili
    FROM ERP_BI_LEDGERTRANS
    WHERE 1=1 ${cw} ${aw}
    GROUP BY MONTH(TRANSDATE), YEAR(TRANSDATE), MAINACCOUNTNUM`;

  query(qButce, [], (e1, butce) => {
    if (e1) return err(res, e1);
    query(qFiili, [], (e2, fiili) => {
      if (e2) return err(res, e2);
      ok(res, {
        butce: butce.map(r => ({
          ay: r.ay, yil: r.yil, hesap: r.ACCOUNTNUM||'', model: r.MODELNUM||'',
          butce: parseFloat(r.butce)||0
        })),
        fiili: fiili.map(r => ({
          ay: r.ay, yil: r.yil, hesap: r.MAINACCOUNTNUM||'',
          fiili: parseFloat(r.fiili)||0
        }))
      });
    });
  });
});

// ═══════════════════════════════════════════════════════
// 17. BİLANÇO
// ═══════════════════════════════════════════════════════
route('/api/bilanco', (req, res, f) => {
  const cw = companyWhere(f.company);
  const aw = ayWhere(f);

  const q = `
    SELECT
      L.MAINACCOUNTNUM,
      H.ACCOUNTNAME,
      H.ACCOUNTPLTYPE,
      SUM(L.AMOUNTMST) AS bakiye
    FROM ERP_BI_LEDGERTRANS L
    LEFT JOIN ERP_BI_HESAPPLANI H ON H.MAINACCOUNTID = L.MAINACCOUNTNUM
    WHERE LEFT(L.MAINACCOUNTNUM,10) < '600'
      ${cw} ${aw}
    GROUP BY L.MAINACCOUNTNUM, H.ACCOUNTNAME, H.ACCOUNTPLTYPE
    ORDER BY L.MAINACCOUNTNUM`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap  : r.MAINACCOUNTNUM,
      isim   : r.ACCOUNTNAME   || '',
      tip    : r.ACCOUNTPLTYPE || '',
      bakiye : parseFloat(r.bakiye) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 18. AÇIK SİPARİŞLER
// ═══════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════
// 18. AÇIK SİPARİŞLER — ERP_BI_ACIKSIPARIS
// ═══════════════════════════════════════════════════════
route('/api/acikSiparis', (req, res, f) => {
  const cw           = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const musteriFilter = f.musteri ? `AND ACCOUNTNUM = '${f.musteri}'`         : '';
  const statusFilter  = f.dim1   ? `AND ORDERSTATUS = ${parseInt(f.dim1)||0}` : '';
  const tipFilter     = f.dim2   ? `AND ORDERTYPE = '${f.dim2}'`              : '';

  const q = `
    SELECT TOP ${f.limit}
      ORDERID,
      ORDERTYPE,
      ITEMID,
      ITEMNAME,
      ACCOUNTNUM,
      ORDERNAME,
      QTYORDERED,
      REMAINQTY,
      LINEAMOUNT,
      ORDERSTATUS,
      DELIVERYDATE,
      SHIPPINGDATECONFIRMED,
      DATEDIFF(DAY, DELIVERYDATE, GETDATE()) AS gecikme
    FROM ERP_BI_ACIKSIPARIS
    WHERE REMAINQTY > 0
      AND ORDERSTATUS NOT IN (4, 5)
      ${cw} ${musteriFilter} ${statusFilter} ${tipFilter}
    ORDER BY gecikme DESC, DELIVERYDATE`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      sipNo   : r.ORDERID,
      tip     : r.ORDERTYPE    || '',
      itemId  : r.ITEMID       || '',
      isim    : r.ITEMNAME     || '',
      musteri : r.ACCOUNTNUM   || '',
      ad      : r.ORDERNAME    || '',
      miktar  : parseFloat(r.QTYORDERED) || 0,
      kalan   : parseFloat(r.REMAINQTY)  || 0,
      tutar   : parseFloat(r.LINEAMOUNT) || 0,
      status  : r.ORDERSTATUS,
      teslim  : r.DELIVERYDATE,
      gecikme : parseInt(r.gecikme) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 19. CARİ HESAP BAKİYE — ERP_BI_CARI
// ═══════════════════════════════════════════════════════
route('/api/cari', (req, res, f) => {
  const cw = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';

  const q = `
    SELECT
      CARITYPE,
      ACCOUNTNUM,
      CARINAME,
      GROUPID,
      TOTALMST,
      OPENMST,
      TRANSCOUNT,
      LASTTRANS
    FROM ERP_BI_CARI
    WHERE 1=1 ${cw}
    ORDER BY ABS(OPENMST) DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      tip     : r.CARITYPE   || '',
      hesap   : r.ACCOUNTNUM || '',
      isim    : r.CARINAME   || '',
      grup    : r.GROUPID    || '',
      toplam  : parseFloat(r.TOTALMST)  || 0,
      acik    : parseFloat(r.OPENMST)   || 0,
      sayac   : parseInt(r.TRANSCOUNT)  || 0,
      sonTarih: r.LASTTRANS
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 20. FİNANSAL BOYUTLAR
// ═══════════════════════════════════════════════════════
route('/api/boyutFinans', (req, res, f) => {
  const cw = companyWhere(f.company);
  const aw = ayWhere(f);
  const d1 = f.dim1 ? `AND DIMENSION  = '${f.dim1}'`  : '';
  const d2 = f.dim2 ? `AND DIMENSION2_ = '${f.dim2}'` : '';
  const d3 = f.dim3 ? `AND DIMENSION3_ = '${f.dim3}'` : '';
  const d4 = f.dim1 ? `AND DIMENSION4_  = '${f.dim1}'`  : '';
  const d5 = f.dim2 ? `AND DIMENSION5_ = '${f.dim2}'` : '';
  const d6 = f.dim3 ? `AND DIMENSION6_ = '${f.dim3}'` : '';

  const q = `
    SELECT
      DIMENSION,
      DIMENSION2_,
      MAINACCOUNTNUM,
      SUM(CASE WHEN LEFT(MAINACCOUNTNUM,10) BETWEEN '600' AND '619' THEN AMOUNTMST * -1 ELSE 0 END) AS gelir,
      SUM(CASE WHEN LEFT(MAINACCOUNTNUM,10) BETWEEN '620' AND '629' THEN AMOUNTMST       ELSE 0 END) AS smm,
      SUM(CASE WHEN LEFT(MAINACCOUNTNUM,10) BETWEEN '630' AND '679' THEN AMOUNTMST       ELSE 0 END) AS gider
    FROM ERP_BI_LEDGERTRANS
    WHERE LEFT(MAINACCOUNTNUM,10) BETWEEN '600' AND '699'
      ${cw} ${aw} ${d1} ${d2} ${d3}
    GROUP BY DIMENSION, DIMENSION2_, MAINACCOUNTNUM
    ORDER BY DIMENSION, MAINACCOUNTNUM`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      isBirimi : r.DIMENSION  || '',
      masrafM  : r.DIMENSION2_ || '',
      hesap    : r.MAINACCOUNTNUM,
      gelir    : parseFloat(r.gelir) || 0,
      smm      : parseFloat(r.smm)   || 0,
      gider    : parseFloat(r.gider) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 21. STOK BOYUTLARI — ERP_BI_INVENTTRANS
// ═══════════════════════════════════════════════════════
route('/api/boyutStok', (req, res, f) => {
  const cw          = f.company && f.company !== 'DAT' ? `AND T.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const depoFilter  = f.depo    ? `AND T.INVENTLOCATIONID = '${f.depo}'`  : '';
  const renkFilter  = f.renk    ? `AND T.INVENTCOLORID    = '${f.renk}'`  : '';
  const boyutFilter = f.boyut   ? `AND T.INVENTSIZEID     = '${f.boyut}'` : '';
  const cfgFilter   = f.config  ? `AND T.CONFIGID         = '${f.config}'`: '';

  const q = `
    SELECT
      T.INVENTLOCATIONID  AS depo,
      T.INVENTCOLORID     AS renk,
      T.INVENTSIZEID      AS ebat,
      T.CONFIGID          AS config,
      COUNT(DISTINCT T.ITEMID)    AS kalemSayisi,
      SUM(T.QTY)                  AS toplamMiktar,
      SUM(T.COSTAMOUNTPOSTED)     AS toplamDeger
    FROM ERP_BI_INVENTTRANS T
    WHERE 1=1
      ${cw} ${depoFilter} ${renkFilter} ${boyutFilter} ${cfgFilter}
    GROUP BY T.INVENTLOCATIONID, T.INVENTCOLORID, T.INVENTSIZEID, T.CONFIGID
    HAVING SUM(T.QTY) > 0
    ORDER BY toplamDeger DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      depo   : r.depo   || '',
      renk   : r.renk   || '',
      ebat   : r.ebat   || '',
      config : r.config || '',
      kalem  : parseInt(r.kalemSayisi)  || 0,
      miktar : parseFloat(r.toplamMiktar) || 0,
      deger  : parseFloat(r.toplamDeger)  || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// 22. SATIN ALMA — ERP_BI_SATINALMA
// ═══════════════════════════════════════════════════════
route('/api/satin', (req, res, f) => {
  const cw         = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw         = ayWhere(f, '');
  const saticiFilter = f.satici  ? `AND NAME LIKE '%${f.satici}%'`       : '';
  const grpFilter    = f.maddeGr ? `AND ITEMID LIKE '${f.maddeGr}%'`     : '';
  const maddeFilter  = f.madde   ? `AND ITEMID = '${f.madde}'`            : '';

  const q = `
    SELECT
      MONTH(INVOICEDATE)    AS ay,
      YEAR(INVOICEDATE)     AS yil,
      PURCHID,
      ITEMID,
      NAME                  AS saticiAdi,
      SUM(LINEAMOUNTMST)    AS tutar,
      SUM(QTY)              AS miktar
    FROM ERP_BI_SATINALMA
    WHERE INVOICEDATE IS NOT NULL
      ${cw}
      AND (${f.aylarList?.length > 0
        ? f.aylarList.map(d=>`(YEAR(INVOICEDATE)=${d.yil} AND MONTH(INVOICEDATE)=${d.ay})`).join(' OR ')
        : `YEAR(INVOICEDATE) = ${f.yil}`})
      ${saticiFilter} ${grpFilter} ${maddeFilter}
    GROUP BY MONTH(INVOICEDATE), YEAR(INVOICEDATE), PURCHID, ITEMID, NAME
    ORDER BY ay`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      ay      : r.ay,
      yil     : r.yil,
      purchId : r.PURCHID   || '',
      itemId  : r.ITEMID    || '',
      satici  : r.saticiAdi || '',
      tutar   : parseFloat(r.tutar)  || 0,
      miktar  : parseFloat(r.miktar) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════
// SABİT KIYMET ANALİZİ — ERP_BI_SABITKIYMET + ERP_BI_SABITKIYMETKARTI
// ═══════════════════════════════════════════════════════
route('/api/sabitKiymet', (req, res, f) => {
  const cw  = f.company && f.company !== 'DAT' ? `AND T.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw  = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(T.TRANSDATE)=${d.yil} AND MONTH(T.TRANSDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(T.TRANSDATE) = ${f.yil}`;
  const grpFilter = f.dim1 ? `AND T.ASSETGROUP = '${f.dim1}'` : '';

  const q = `
    SELECT
      T.ASSETID,
      T.ASSETGROUP,
      K.NAME          AS varlikAdi,
      K.LOCATION      AS konum,
      T.BOOKID,
      T.TRANSTYPE,
      MONTH(T.TRANSDATE)  AS ay,
      YEAR(T.TRANSDATE)   AS yil,
      SUM(T.AMOUNTMST)    AS tutar
    FROM ERP_BI_SABITKIYMET T
    LEFT JOIN ERP_BI_SABITKIYMETKARTI K ON K.ASSETID = T.ASSETID AND K.DATAAREAID = T.DATAAREAID
    WHERE T.TRANSDATE IS NOT NULL
      ${cw} ${aw} ${grpFilter}
    GROUP BY T.ASSETID, T.ASSETGROUP, K.NAME, K.LOCATION, T.BOOKID, T.TRANSTYPE,
             MONTH(T.TRANSDATE), YEAR(T.TRANSDATE)
    ORDER BY T.ASSETGROUP, T.ASSETID`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      assetId  : r.ASSETID    || '',
      grup     : r.ASSETGROUP || '',
      isim     : r.varlikAdi  || '',
      konum    : r.konum      || '',
      defter   : r.BOOKID     || '',
      tip      : r.TRANSTYPE,
      ay       : r.ay,
      yil      : r.yil,
      tutar    : parseFloat(r.tutar) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// BÜTÇE vs FİİLİ SATIŞ — ERP_BI_BUTCE_SATIS + ERP_BI_SATISFATURA
// ═══════════════════════════════════════════════════════
route('/api/butceSatis', (req, res, f) => {
  const cw  = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw  = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(TRANSDATE)=${d.yil} AND MONTH(TRANSDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(TRANSDATE) = ${f.yil}`;

  const qButce = `
    SELECT
      MONTH(TRANSDATE) AS ay,
      ITEMID,
      ITEMNAME,
      SUM(SALESQTY)        AS butceAdet,
      SUM(TOTALPRICETRY)   AS butceTutar
    FROM ERP_BI_BUTCE_SATIS
    WHERE TRANSDATE IS NOT NULL AND DOCUMENTSTATUS IN (1,2,3)
      ${cw} ${aw}
    GROUP BY MONTH(TRANSDATE), ITEMID, ITEMNAME
    ORDER BY ay, ITEMID`;

  const awFat = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(INVOICEDATE)=${d.yil} AND MONTH(INVOICEDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(INVOICEDATE) = ${f.yil}`;
  const cwFat = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';

  const qFiili = `
    SELECT
      MONTH(INVOICEDATE) AS ay,
      ITEMID,
      SUM(QTY)           AS fiiliAdet,
      SUM(LINEAMOUNTMST) AS fiiliTutar
    FROM ERP_BI_SATISFATURA
    WHERE INVOICEDATE IS NOT NULL
      ${cwFat} ${awFat}
    GROUP BY MONTH(INVOICEDATE), ITEMID
    ORDER BY ay, ITEMID`;

  query(qButce, [], (e1, butce) => {
    if (e1) return err(res, e1);
    query(qFiili, [], (e2, fiili) => {
      if (e2) return err(res, e2);
      ok(res, {
        butce: butce.map(r => ({
          ay: r.ay, itemId: r.ITEMID||'', isim: r.ITEMNAME||'',
          adet: parseFloat(r.butceAdet)||0, tutar: parseFloat(r.butceTutar)||0
        })),
        fiili: fiili.map(r => ({
          ay: r.ay, itemId: r.ITEMID||'',
          adet: parseFloat(r.fiiliAdet)||0, tutar: parseFloat(r.fiiliTutar)||0
        }))
      });
    });
  });
});

// ═══════════════════════════════════════════════════════
// MÜŞTERİ RİSK / LİMİT — ERP_BI_ALACAK + ERP_BI_MUSTERIKARTI
// ═══════════════════════════════════════════════════════
route('/api/musteriRisk', (req, res, f) => {
  const cw = f.company && f.company !== 'DAT' ? `AND A.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';

  const q = `
    SELECT
      A.ACCOUNTNUM,
      A.CUSTNAME,
      A.CUSTGROUP,
      M.PAYMTERMID,
      SUM(A.AMOUNTMST)                                    AS toplamBorc,
      SUM(A.OPENAMOUNTMST)                                AS acikBorc,
      MAX(A.AGINGDAYS)                                    AS maxVadeGun,
      SUM(CASE WHEN A.AGINGDAYS > 0  AND A.AGINGDAYS <= 30  THEN A.OPENAMOUNTMST ELSE 0 END) AS bant30,
      SUM(CASE WHEN A.AGINGDAYS > 30 AND A.AGINGDAYS <= 60  THEN A.OPENAMOUNTMST ELSE 0 END) AS bant60,
      SUM(CASE WHEN A.AGINGDAYS > 60 AND A.AGINGDAYS <= 90  THEN A.OPENAMOUNTMST ELSE 0 END) AS bant90,
      SUM(CASE WHEN A.AGINGDAYS > 90                         THEN A.OPENAMOUNTMST ELSE 0 END) AS bant90p,
      COUNT(A.RECID)                                      AS islemSayisi
    FROM ERP_BI_ALACAK A
    LEFT JOIN ERP_BI_MUSTERIKARTI M ON M.CUSTACCOUNT = A.ACCOUNTNUM AND M.DATAAREAID = A.DATAAREAID
    WHERE A.CLOSED IS NULL
      ${cw}
    GROUP BY A.ACCOUNTNUM, A.CUSTNAME, A.CUSTGROUP, M.PAYMTERMID
    ORDER BY acikBorc DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap    : r.ACCOUNTNUM || '',
      isim     : r.CUSTNAME   || '',
      grup     : r.CUSTGROUP  || '',
      vadeTerm : r.PAYMTERMID || '',
      toplam   : parseFloat(r.toplamBorc) || 0,
      acik     : parseFloat(r.acikBorc)   || 0,
      maxGun   : parseInt(r.maxVadeGun)   || 0,
      b30      : parseFloat(r.bant30)  || 0,
      b60      : parseFloat(r.bant60)  || 0,
      b90      : parseFloat(r.bant90)  || 0,
      b90p     : parseFloat(r.bant90p) || 0,
      islem    : parseInt(r.islemSayisi) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// TEDARİKÇİ PERFORMANS — ERP_BI_SATINALMA + ERP_BI_SATICIKARTI + ERP_BI_BORC
// ═══════════════════════════════════════════════════════
route('/api/saticiPerf', (req, res, f) => {
  const cw = f.company && f.company !== 'DAT' ? `AND S.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(S.INVOICEDATE)=${d.yil} AND MONTH(S.INVOICEDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(S.INVOICEDATE) = ${f.yil}`;

  const q = `
    SELECT
      S.NAME                        AS saticiAdi,
      K.VENDACCOUNT,
      K.VENDGROUPID,
      K.VENDGROUPNAME,
      COUNT(DISTINCT S.PURCHID)     AS siparisAdet,
      SUM(S.QTY)                    AS toplamAdet,
      SUM(S.LINEAMOUNTMST)          AS toplamTutar,
      AVG(S.LINEAMOUNTMST)          AS ortTutar,
      MIN(S.INVOICEDATE)            AS ilkFatura,
      MAX(S.INVOICEDATE)            AS sonFatura
    FROM ERP_BI_SATINALMA S
    LEFT JOIN ERP_BI_SATICIKARTI K ON K.VENDNAME = S.NAME AND K.DATAAREAID = S.DATAAREAID
    WHERE S.INVOICEDATE IS NOT NULL
      ${cw} ${aw}
    GROUP BY S.NAME, K.VENDACCOUNT, K.VENDGROUPID, K.VENDGROUPNAME
    ORDER BY toplamTutar DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap    : r.VENDACCOUNT  || '',
      isim     : r.saticiAdi    || '',
      grup     : r.VENDGROUPID  || '',
      grpAd    : r.VENDGROUPNAME|| '',
      sipAdet  : parseInt(r.siparisAdet)   || 0,
      adet     : parseFloat(r.toplamAdet)  || 0,
      tutar    : parseFloat(r.toplamTutar) || 0,
      ortTutar : parseFloat(r.ortTutar)    || 0,
      ilk      : r.ilkFatura,
      son      : r.sonFatura
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// PERSONEL LİSTESİ — ERP_BI_PERSONEL
// ═══════════════════════════════════════════════════════
route('/api/personel', (req, res, f) => {
  const search = f.arama ? `WHERE NAME LIKE '%${f.arama}%' OR PERSONNELNUMBER LIKE '%${f.arama}%'` : '';

  const q = `
    SELECT TOP ${f.limit}
      PERSONNELNUMBER,
      NAME
    FROM ERP_BI_PERSONEL
    ${search}
    ORDER BY NAME`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      sicil : r.PERSONNELNUMBER || '',
      isim  : r.NAME            || ''
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// FİLTRE DEĞERLERİ — dinamik dropdown doldurma
// ═══════════════════════════════════════════════════════
route('/api/filtreDeger', (req, res, f) => {
  const tip = f.tip || '';
  const cw  = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const cwL = companyWhere(f.company);

  const queries = {
    // Finansal boyutlar — ERP_BI_LEDGERTRANS (çok veri — TOP 1000000)
    dimension1: `SELECT DISTINCT TOP 200 DIMENSION AS val FROM ERP_BI_LEDGERTRANS WHERE DIMENSION IS NOT NULL AND DIMENSION <> '' ${cwL} ORDER BY val`,
    dimension2: `SELECT DISTINCT TOP 200 DIMENSION2_ AS val FROM ERP_BI_LEDGERTRANS WHERE DIMENSION2_ IS NOT NULL AND DIMENSION2_ <> '' ${cwL} ORDER BY val`,
    dimension3: `SELECT DISTINCT TOP 200 DIMENSION3_ AS val FROM ERP_BI_LEDGERTRANS WHERE DIMENSION3_ IS NOT NULL AND DIMENSION3_ <> '' ${cwL} ORDER BY val`,
    dimension4: `SELECT DISTINCT TOP 200 DIMENSION4_ AS val FROM ERP_BI_LEDGERTRANS WHERE DIMENSION4_ IS NOT NULL AND DIMENSION4_ <> '' ${cwL} ORDER BY val`,

    // Hesap planı — MAINACCOUNTID + ACCOUNTNAME
    hesap: `SELECT MAINACCOUNTID AS val, ACCOUNTNAME AS label FROM ERP_BI_HESAPPLANI WHERE MAINACCOUNTID IS NOT NULL ORDER BY val`,

    // Madde grubu — INVENTITEMGROUPNAME daha anlamlı
    maddeGrubu: `SELECT DISTINCT M.INVENTITEMGROUPID AS val, MAX(M.INVENTITEMGROUPNAME) AS label FROM ERP_BI_MADDEKARTI M WHERE M.INVENTITEMGROUPID IS NOT NULL AND M.INVENTITEMGROUPID <> '' ${cw.replace('DATAAREAID', 'M.DATAAREAID')} GROUP BY M.INVENTITEMGROUPID ORDER BY val`,

    // Stok boyutları — ERP_BI_INVENTTRANS
    tesis:  `SELECT DISTINCT INVENTSITEID AS val FROM ERP_BI_INVENTTRANS WHERE INVENTSITEID IS NOT NULL AND INVENTSITEID <> '' ${cw} ORDER BY val`,
    depo:   `SELECT DISTINCT INVENTLOCATIONID AS val FROM ERP_BI_INVENTTRANS WHERE INVENTLOCATIONID IS NOT NULL AND INVENTLOCATIONID <> '' ${cw} ORDER BY val`,
    renk:   `SELECT DISTINCT INVENTCOLORID AS val FROM ERP_BI_INVENTTRANS WHERE INVENTCOLORID IS NOT NULL AND INVENTCOLORID <> '' ${cw} ORDER BY val`,
    ebat:   `SELECT DISTINCT INVENTSIZEID AS val FROM ERP_BI_INVENTTRANS WHERE INVENTSIZEID IS NOT NULL AND INVENTSIZEID <> '' ${cw} ORDER BY val`,
    config: `SELECT DISTINCT CONFIGID AS val FROM ERP_BI_INVENTTRANS WHERE CONFIGID IS NOT NULL AND CONFIGID <> '' ${cw} ORDER BY val`,
    parti:  `SELECT DISTINCT TOP 200 INVENTBATCHID AS val FROM ERP_BI_INVENTTRANS WHERE INVENTBATCHID IS NOT NULL AND INVENTBATCHID <> '' ${cw} ORDER BY val`,

    // Müşteri grubu — CUSTGROUPNAME daha anlamlı
    musteriGrubu:    `SELECT DISTINCT CUSTGROUPID AS val, CUSTGROUPNAME AS label FROM ERP_BI_MUSTERIKARTI WHERE CUSTGROUPID IS NOT NULL AND CUSTGROUPID <> '' ${cw} ORDER BY val`,
    musteriGrAlacak: `SELECT DISTINCT CUSTGROUP AS val, CUSTGROUP AS label FROM ERP_BI_ALACAK WHERE CUSTGROUP IS NOT NULL AND CUSTGROUP <> '' ${cw} ORDER BY val`,

    // Satıcı grubu — VENDGROUPNAME daha anlamlı
    saticiGrubu:  `SELECT DISTINCT VENDGROUPID AS val, VENDGROUPNAME AS label FROM ERP_BI_SATICIKARTI WHERE VENDGROUPID IS NOT NULL AND VENDGROUPID <> '' ${cw} ORDER BY val`,
    saticiGrBorc: `SELECT DISTINCT VENDGROUP AS val, VENDGROUP AS label FROM ERP_BI_BORC WHERE VENDGROUP IS NOT NULL AND VENDGROUP <> '' ${cw} ORDER BY val`,

    // Banka hesabı — ACCOUNTID + BANKNAME
    bankaHesabi: `SELECT DISTINCT B.ACCOUNTID AS val, ISNULL(K.NAME, B.ACCOUNTID) AS label FROM ERP_BI_BANKA B LEFT JOIN ERP_BI_BANKAKARTI K ON K.ACCOUNTID = B.ACCOUNTID AND K.DATAAREAID = B.DATAAREAID WHERE B.ACCOUNTID IS NOT NULL ${cw.replace('DATAAREAID', 'B.DATAAREAID')} ORDER BY label`,

    // KDV kodu — TAXGROUP
    kdvKodu:     `SELECT DISTINCT TAXGROUP AS val FROM ERP_BI_KDV WHERE TAXGROUP IS NOT NULL AND TAXGROUP <> '' ${cw} ORDER BY val`,
    kdvItemGrubu:`SELECT DISTINCT TAXITEMGROUP AS val FROM ERP_BI_KDV WHERE TAXITEMGROUP IS NOT NULL AND TAXITEMGROUP <> '' ${cw} ORDER BY val`,

    // Üretim grubu — ERP_BI_INVENTTRANS kaynak grubu
    prodGrubu: `SELECT DISTINCT INVENTLOCATIONID AS val FROM ERP_BI_URETIMEMRI WHERE INVENTLOCATIONID IS NOT NULL AND INVENTLOCATIONID <> '' ${cw} ORDER BY val`,

    // Sabit kıymet grubu
    assetGrubu: `SELECT DISTINCT ASSETGROUP AS val FROM ERP_BI_SABITKIYMET WHERE ASSETGROUP IS NOT NULL AND ASSETGROUP <> '' ${cw} ORDER BY val`,

    // Bütçe modeli
    butceModel: `SELECT DISTINCT MODELNUM AS val FROM ERP_BI_BUTCE_MUHASEBE WHERE MODELNUM IS NOT NULL AND MODELNUM <> '' ${cw} ORDER BY val`,

    // Cari grubu
    cariGrubu: `SELECT DISTINCT GROUPID AS val FROM ERP_BI_CARI WHERE GROUPID IS NOT NULL AND GROUPID <> '' ${cw} ORDER BY val`,

    // Satisfatura boyutları (satış ve satın alma için)
    satDim1: `SELECT DISTINCT TOP 1000000 DIMENSION AS val FROM ERP_BI_SATISFATURA WHERE DIMENSION IS NOT NULL AND DIMENSION <> '' ${cw} ORDER BY val`,
    satDim2: `SELECT DISTINCT TOP 1000000 DIMENSION2_ AS val FROM ERP_BI_SATISFATURA WHERE DIMENSION2_ IS NOT NULL AND DIMENSION2_ <> '' ${cw} ORDER BY val`,
    satDim3: `SELECT DISTINCT TOP 1000000 DIMENSION3_ AS val FROM ERP_BI_SATISFATURA WHERE DIMENSION3_ IS NOT NULL AND DIMENSION3_ <> '' ${cw} ORDER BY val`,
    satinDim1: `SELECT DISTINCT TOP 1000000 DIMENSION AS val FROM ERP_BI_SATINALMA WHERE DIMENSION IS NOT NULL AND DIMENSION <> '' ${cw} ORDER BY val`,
    satinDim2: `SELECT DISTINCT TOP 1000000 DIMENSION2_ AS val FROM ERP_BI_SATINALMA WHERE DIMENSION2_ IS NOT NULL AND DIMENSION2_ <> '' ${cw} ORDER BY val`,
  };

  const q = queries[tip];
  if (!q) return ok(res, { rows: [], error: `Bilinmeyen tip: ${tip}` });

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      val   : String(r.val   || '').trim(),
      label : String(r.label || r.val || '').trim()
    })).filter(r => r.val) });
  });
});


route('/api/urunKar', (req, res, f) => {
  const cw = f.company && f.company !== 'DAT' ? `AND S.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(S.INVOICEDATE)=${d.yil} AND MONTH(S.INVOICEDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(S.INVOICEDATE) = ${f.yil}`;
  const grpFilter = f.maddeGr ? `AND M.ITEMGROUPID = '${f.maddeGr}'` : '';

  const q = `
    SELECT TOP ${f.limit}
      S.ITEMID,
      M.ITEMNAME,
      M.ITEMGROUPID,
      SUM(S.LINEAMOUNTMST)        AS ciro,
      SUM(S.QTY)                  AS miktar,
      COUNT(DISTINCT S.INVOICEID) AS faturaAdet
    FROM ERP_BI_SATISFATURA S
    LEFT JOIN ERP_BI_MADDEKARTI M ON M.ITEMID = S.ITEMID AND M.DATAAREAID = S.DATAAREAID
    WHERE S.INVOICEDATE IS NOT NULL
      ${cw} ${aw} ${grpFilter}
    GROUP BY S.ITEMID, M.ITEMNAME, M.ITEMGROUPID
    ORDER BY ciro DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      itemId  : r.ITEMID       || '',
      isim    : r.ITEMNAME     || '',
      grup    : r.ITEMGROUPID  || '',
      ciro    : parseFloat(r.ciro)    || 0,
      miktar  : parseFloat(r.miktar)  || 0,
      fatura  : parseInt(r.faturaAdet)|| 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// CARİ TREND — ERP_BI_ALACAK + ERP_BI_BORC aylık
// ═══════════════════════════════════════════════════════
route('/api/cariTrend', (req, res, f) => {
  const cw = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw = `AND YEAR(TRANSDATE) = ${f.yil}`;

  const qAl = `
    SELECT MONTH(TRANSDATE) AS ay, SUM(OPENAMOUNTMST) AS tutar
    FROM ERP_BI_ALACAK WHERE (CLOSED IS NULL OR CLOSED <= '1900-01-02') AND OPENAMOUNTMST <> 0 ${cw} ${aw}
    GROUP BY MONTH(TRANSDATE) ORDER BY ay`;

  const qBr = `
    SELECT MONTH(TRANSDATE) AS ay, SUM(OPENAMOUNTMST) AS tutar
    FROM ERP_BI_BORC WHERE (CLOSED IS NULL OR CLOSED <= '1900-01-02') AND OPENAMOUNTMST <> 0 ${cw} ${aw}
    GROUP BY MONTH(TRANSDATE) ORDER BY ay`;

  query(qAl, [], (e1, alacak) => {
    if (e1) return err(res, e1);
    query(qBr, [], (e2, borc) => {
      if (e2) return err(res, e2);
      ok(res, {
        alacak: alacak.map(r => ({ ay: r.ay, tutar: parseFloat(r.tutar)||0 })),
        borc:   borc.map(r =>   ({ ay: r.ay, tutar: parseFloat(r.tutar)||0 }))
      });
    });
  });
});

// ═══════════════════════════════════════════════════════
// STOK DEVİR HIZI — ERP_BI_INVENTTRANS
// ═══════════════════════════════════════════════════════
route('/api/stokDevir', (req, res, f) => {
  const cw      = f.company && f.company !== 'DAT' ? `AND T.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw      = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(T.DATEPHYSICAL)=${d.yil} AND MONTH(T.DATEPHYSICAL)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(T.DATEPHYSICAL) = ${f.yil}`;
  const grpFilter = f.maddeGr ? `AND M.ITEMGROUPID = '${f.maddeGr}'` : '';

  const q = `
    SELECT
      M.ITEMGROUPID,
      SUM(CASE WHEN T.STATUSISSUE  >= 1 THEN ABS(T.COSTAMOUNTPOSTED) ELSE 0 END) AS satisMAliyet,
      AVG(ABS(T.COSTAMOUNTPOSTED))                                                AS ortStok,
      COUNT(DISTINCT T.ITEMID)                                                    AS kalemSayisi
    FROM ERP_BI_INVENTTRANS T
    LEFT JOIN ERP_BI_MADDEKARTI M ON M.ITEMID = T.ITEMID AND M.DATAAREAID = T.DATAAREAID
    WHERE T.DATEPHYSICAL IS NOT NULL
      ${cw} ${aw} ${grpFilter}
    GROUP BY M.ITEMGROUPID
    ORDER BY satisMAliyet DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      grup        : r.ITEMGROUPID   || 'Diğer',
      satisMaliyet: parseFloat(r.satisMAliyet) || 0,
      ortStok     : parseFloat(r.ortStok)      || 0,
      kalem       : parseInt(r.kalemSayisi)    || 0,
      devirHizi   : r.ortStok > 0 ? parseFloat((r.satisMAliyet / r.ortStok).toFixed(2)) : 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// GİDER DETAYI — ERP_BI_LEDGERTRANS 6xx/7xx
// ═══════════════════════════════════════════════════════
route('/api/giderDetay', (req, res, f) => {
  const cw  = companyWhere(f.company);
  const aw  = ayWhere(f);
  const d1  = f.dim1 ? `AND DIMENSION  = '${f.dim1}'`  : '';
  const d2  = f.dim2 ? `AND DIMENSION2_ = '${f.dim2}'` : '';
  const d3  = f.dim3 ? `AND DIMENSION3_ = '${f.dim3}'` : '';

  const q = `
    SELECT
      MAINACCOUNTNUM,
      H.ACCOUNTNAME,
      DIMENSION,
      DIMENSION2_,
      DIMENSION3_,
      MONTH(TRANSDATE) AS ay,
      SUM(AMOUNTMST)   AS tutar
    FROM ERP_BI_LEDGERTRANS L
    LEFT JOIN ERP_BI_HESAPPLANI H ON H.MAINACCOUNTID = L.MAINACCOUNTNUM
    WHERE LEFT(L.MAINACCOUNTNUM,10) BETWEEN '600' AND '799'
      ${cw} ${aw} ${d1} ${d2} ${d3}
    GROUP BY MAINACCOUNTNUM, H.ACCOUNTNAME, DIMENSION, DIMENSION2_, DIMENSION3_, MONTH(TRANSDATE)
    ORDER BY tutar DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap   : r.MAINACCOUNTNUM || '',
      isim    : r.ACCOUNTNAME    || '',
      dim1    : r.DIMENSION      || '',
      dim2    : r.DIMENSION2_    || '',
      dim3    : r.DIMENSION3_    || '',
      ay      : r.ay,
      tutar   : parseFloat(r.tutar) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// MÜŞTERİ-ÜRÜN KÂRLILIK MATRİSİ
// ═══════════════════════════════════════════════════════
route('/api/musteriUrunKar', (req, res, f) => {
  const cw = f.company && f.company !== 'DAT'
    ? `AND S.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(S.INVOICEDATE)=${d.yil} AND MONTH(S.INVOICEDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(S.INVOICEDATE) = ${f.yil}`;

  const musteriFilter  = f.musteri  ? `AND S.INVOICEACCOUNT = '${f.musteri}'`  : '';
  const musteriGrFilter= f.musteriGr? `AND K.CUSTGROUPID = '${f.musteriGr}'`   : '';
  const maddeGrFilter  = f.maddeGr  ? `AND M.INVENTITEMGROUPID = '${f.maddeGr}'` : '';
  const itemFilter     = f.item     ? `AND S.ITEMID LIKE '%${f.item}%'`         : '';
  const limitVal       = parseInt(f.limit) || 5000000000;

  const q = `
    SELECT TOP ${limitVal}
      S.INVOICEACCOUNT                            AS musteriKodu,
      ISNULL(K.CUSTNAME, S.INVOICEACCOUNT)        AS musteriAdi,
      ISNULL(K.CUSTGROUPID,'')                    AS musteriGrubu,
      S.ITEMID                                    AS itemId,
      ISNULL(M.ITEMNAME, S.ITEMID)                AS itemAdi,
      ISNULL(M.INVENTITEMGROUPID,'')              AS itemGrubu,
      SUM(S.QTY)                                  AS miktar,
      SUM(S.SALESUNIT)                            AS birim,
      SUM(S.LINEAMOUNTMST)                        AS satisTutar,
      SUM(ABS(ISNULL(I.COSTAMOUNTPOSTED,0))
        + ABS(ISNULL(I.COSTAMOUNTADJUSTMENT,0)))  AS maliyet,
      SUM(S.LINEAMOUNTMST)
        - SUM(ABS(ISNULL(I.COSTAMOUNTPOSTED,0))
        + ABS(ISNULL(I.COSTAMOUNTADJUSTMENT,0)))  AS brutKar
    FROM ERP_BI_SATISFATURA S
    LEFT JOIN ERP_BI_MUSTERIKARTI K
      ON  K.CUSTACCOUNT = S.INVOICEACCOUNT
      AND K.DATAAREAID  = S.DATAAREAID
    LEFT JOIN ERP_BI_MADDEKARTI M
      ON  M.ITEMID      = S.ITEMID
      AND M.DATAAREAID  = S.DATAAREAID
    LEFT JOIN ERP_BI_INVENTTRANS I
      ON  I.INVENTTRANSID = S.INVENTTRANSID
      AND I.DATAAREAID    = S.DATAAREAID
    WHERE S.INVOICEDATE IS NOT NULL
      ${cw} ${aw}
      ${musteriFilter} ${musteriGrFilter}
      ${maddeGrFilter} ${itemFilter}
    GROUP BY
      S.INVOICEACCOUNT, K.CUSTNAME, K.CUSTGROUPID,
      S.ITEMID, M.ITEMNAME, M.INVENTITEMGROUPID, S.SALESUNIT
    ORDER BY satisTutar DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      musteriKodu : r.musteriKodu  || '',
      musteriAdi  : r.musteriAdi   || '',
      musteriGrubu: r.musteriGrubu || '',
      itemId      : r.itemId       || '',
      itemAdi     : r.itemAdi      || '',
      itemGrubu   : r.itemGrubu    || '',
      miktar      : parseFloat(r.miktar)     || 0,
      satisTutar  : parseFloat(r.satisTutar) || 0,
      maliyet     : parseFloat(r.maliyet)    || 0,
      brutKar     : parseFloat(r.brutKar)    || 0,
      brutKarPct  : r.satisTutar > 0
        ? parseFloat(((r.brutKar / r.satisTutar) * 100).toFixed(2)) : 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
// KUR — ERP_BI_KUR (USD/EUR/GBP → TRY)
// ═══════════════════════════════════════════════════════
route('/api/kur', (req, res, f) => {
  // Önce view'dan dene, yoksa direkt tablodan çek
  const qView = `
    SELECT DOVIZ, KUR, TARIH
    FROM ERP_BI_KUR
    WHERE TARIH = (SELECT MAX(TARIH) FROM ERP_BI_KUR)
    ORDER BY DOVIZ`;

  const qDirect = `
    SELECT
      CP.FROMCURRENCYCODE AS DOVIZ,
      ER.EXCHANGERATE / 100.0 AS KUR,
      CONVERT(DATE, ER.VALIDFROM) AS TARIH
    FROM EXCHANGERATE ER
    JOIN EXCHANGERATECURRENCYPAIR CP ON CP.RECID = ER.EXCHANGERATECURRENCYPAIR
    JOIN EXCHANGERATETYPE ET ON ET.RECID = CP.EXCHANGERATETYPE
    WHERE CP.FROMCURRENCYCODE IN ('USD','EUR','GBP')
      AND CP.TOCURRENCYCODE = 'TRY'
      AND ET.NAME = 'TCMB_A'
      AND ER.VALIDFROM = (SELECT MAX(VALIDFROM) FROM EXCHANGERATE)
    ORDER BY CP.FROMCURRENCYCODE`;

  query(qView, [], (e, rows) => {
    if (e || !rows || !rows.length) {
      // View yoksa direkt tablodan
      query(qDirect, [], (e2, rows2) => {
        if (e2) return err(res, e2);
        const kurlar = {};
        rows2.forEach(r => { kurlar[r.DOVIZ] = parseFloat(r.KUR) || 0; });
        ok(res, { kurlar, tarih: rows2[0]?.TARIH || null, kaynak: 'DIRECT' });
      });
    } else {
      const kurlar = {};
      rows.forEach(r => { kurlar[r.DOVIZ] = parseFloat(r.KUR) || 0; });
      ok(res, { kurlar, tarih: rows[0]?.TARIH || null, kaynak: 'VIEW' });
    }
  });
});

// /api/kurTarihsel — son 30 günlük kur geçmişi
route('/api/kurTarihsel', (req, res, f) => {
  const doviz = f.doviz || 'USD';
  const q = `
    SELECT TOP 30
      CP.FROMCURRENCYCODE AS DOVIZ,
      ER.EXCHANGERATE / 100.0 AS KUR,
      CONVERT(DATE, ER.VALIDFROM) AS TARIH
    FROM EXCHANGERATE ER
    JOIN EXCHANGERATECURRENCYPAIR CP ON CP.RECID = ER.EXCHANGERATECURRENCYPAIR
    JOIN EXCHANGERATETYPE ET ON ET.RECID = CP.EXCHANGERATETYPE
    WHERE CP.FROMCURRENCYCODE = '${doviz}'
      AND CP.TOCURRENCYCODE = 'TRY'
      AND ET.NAME = 'TCMB_A'
    ORDER BY ER.VALIDFROM DESC`;
  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({ tarih: r.TARIH, kur: parseFloat(r.KUR)||0 })) });
  });
});

// HOLDİNG KONSOLİDE ÖZET


// HOLDİNG KONSOLİDE ÖZET
route('/api/holding', (req, res, f) => {
  const aw = ayWhere(f);
  const companies = ['nt','kk','elm','yty','nfge'];

  // Gelir (60x) ve SMM (62x) — tüm şirketler
  const qGelir = `
    SELECT DATAAREAIDLEDGER,
      SUM(CASE WHEN LEFT(MAINACCOUNTNUM,10) BETWEEN '600' AND '619' THEN AMOUNTMST * -1 ELSE 0 END) AS gelir,
      SUM(CASE WHEN LEFT(MAINACCOUNTNUM,10) BETWEEN '620' AND '629' THEN AMOUNTMST ELSE 0 END) AS smm,
      SUM(CASE WHEN LEFT(MAINACCOUNTNUM,10) BETWEEN '630' AND '699' THEN ABS(AMOUNTMST) ELSE 0 END) AS gider,
      SUM(CASE WHEN LEFT(MAINACCOUNTNUM,10) BETWEEN '730' AND '779' THEN ABS(AMOUNTMST) ELSE 0 END) AS amortisman
    FROM ERP_BI_LEDGERTRANS
    WHERE LEFT(MAINACCOUNTNUM,10) BETWEEN '600' AND '799'
      ${aw.replace('TRANSDATE','TRANSDATE')}
    GROUP BY DATAAREAIDLEDGER`;

  // Nakit (banka bakiyeleri)
  const qNakit = `
    SELECT B.DATAAREAID,
      SUM(B.AMOUNTMST) AS bakiye
    FROM ERP_BI_BANKA B
    WHERE B.CURRENCYCODE = 'TRY'
    GROUP BY B.DATAAREAID`;

  // Alacak (vadesi geçmiş)
  const qAlacak = `
    SELECT A.DATAAREAID,
      SUM(ABS(A.OPENAMOUNTMST)) AS toplamAlacak,
      SUM(CASE WHEN A.AGINGDAYS > 90 THEN ABS(A.OPENAMOUNTMST) ELSE 0 END) AS kritikAlacak
    FROM ERP_BI_ALACAK A
    WHERE A.CLOSED IS NULL
    GROUP BY A.DATAAREAID`;

  // Açık siparişler
  const qSiparis = `
    SELECT DATAAREAID, COUNT(*) AS acikSiparis,
      SUM(REMAINQTY * LINEAMOUNT / NULLIF(QTYORDERED,0)) AS siparisTutar
    FROM ERP_BI_ACIKSIPARIS
    WHERE ORDERSTATUS < 4
    GROUP BY DATAAREAID`;

  const COMPANY_CODE_MAP = {
    '5637147576':'NT','5637147577':'YTY','5637148327':'NFGE',
    '5637148326':'ELM','5637146826':'KK'
  };
  const CODE_RECID = Object.fromEntries(Object.entries(COMPANY_CODE_MAP).map(([k,v])=>[v,k]));

  query(qGelir, [], (e1, gelirRows) => {
    if (e1) return err(res, e1);
    query(qNakit, [], (e2, nakitRows) => {
      if (e2) return err(res, e2);
      query(qAlacak, [], (e3, alacakRows) => {
        if (e3) return err(res, e3);
        query(qSiparis, [], (e4, sipRows) => {
          if (e4) return err(res, e4);

          const nakit   = Object.fromEntries(nakitRows.map(r=>[r.DATAAREAID?.toLowerCase(), parseFloat(r.bakiye)||0]));
          const alacak  = Object.fromEntries(alacakRows.map(r=>[r.DATAAREAID?.toLowerCase(), {
            toplam: parseFloat(r.toplamAlacak)||0, kritik: parseFloat(r.kritikAlacak)||0
          }]));
          const siparis = Object.fromEntries(sipRows.map(r=>[r.DATAAREAID?.toLowerCase(), parseInt(r.acikSiparis)||0]));

          const sirketler = {};
          gelirRows.forEach(r => {
            const name = COMPANY_CODE_MAP[String(r.DATAAREAIDLEDGER)] || String(r.DATAAREAIDLEDGER);
            const code = name.toLowerCase();
            const gelir = parseFloat(r.gelir)||0;
            const smm   = parseFloat(r.smm)||0;
            const gider = parseFloat(r.gider)||0;
            const amort = parseFloat(r.amortisman)||0;
            const brutKar = gelir - smm;
            const faalKar = brutKar - gider;
            const ebitda  = faalKar + amort;
            sirketler[name] = {
              name, code,
              gelir, smm, gider, amort,
              brutKar, faalKar, ebitda,
              brutMarj: gelir > 0 ? (brutKar/gelir*100) : 0,
              ebitdaMarj: gelir > 0 ? (ebitda/gelir*100) : 0,
              nakit: nakit[code] || 0,
              alacak: alacak[code]?.toplam || 0,
              kritikAlacak: alacak[code]?.kritik || 0,
              acikSiparis: siparis[code] || 0,
            };
          });

          // Konsolide toplam
          const toplam = Object.values(sirketler).reduce((acc, s) => ({
            gelir: acc.gelir + s.gelir,
            smm: acc.smm + s.smm,
            brutKar: acc.brutKar + s.brutKar,
            faalKar: acc.faalKar + s.faalKar,
            ebitda: acc.ebitda + s.ebitda,
            nakit: acc.nakit + s.nakit,
            alacak: acc.alacak + s.alacak,
            kritikAlacak: acc.kritikAlacak + s.kritikAlacak,
            acikSiparis: acc.acikSiparis + s.acikSiparis,
          }), { gelir:0,smm:0,brutKar:0,faalKar:0,ebitda:0,nakit:0,alacak:0,kritikAlacak:0,acikSiparis:0 });

          // Alarmlar
          const alarmlar = [];
          Object.values(sirketler).forEach(s => {
            if (s.kritikAlacak > 0) alarmlar.push({ tip:'ALACAK', sirket:s.name, mesaj:`90+ gün alacak`, tutar:s.kritikAlacak });
            if (s.nakit < 0) alarmlar.push({ tip:'NAKİT', sirket:s.name, mesaj:'Negatif nakit', tutar:s.nakit });
            if (s.brutMarj < 10 && s.gelir > 0) alarmlar.push({ tip:'MARJ', sirket:s.name, mesaj:`Düşük marj %${s.brutMarj.toFixed(1)}`, tutar:s.gelir });
          });

          ok(res, { sirketler: Object.values(sirketler), toplam, alarmlar });
        });
      });
    });
  });
});


// ═══════════════════════════════════════════════════════
// KK MALİYET KONTROL — Ocak 2026
// Giriş vs Çıkış: CostAmountPosted + CostAmountAdjustment
// ═══════════════════════════════════════════════════════
route('/api/kkMaliyetOcak', (req, res, f) => {
  const company = f.company || 'KK';
  const cw = f.company && f.company !== 'DAT' ? `AND T.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';

  const baslangic = f.baslangic || '2026-01-01';
  const bitis     = f.bitis     || '2026-01-31';

  const q = `
    SELECT
      T.ITEMID                              AS ItemId,
      M.NAMEALIAS                            AS ItemName,
      ISNULL(M.ERP_ITEMGROUPID,'')           AS ItemGroup,
      ori.REFERENCECATEGORY                  AS RefCat,
      dim.INVENTLOCATIONID                   AS Ambar,
      dim.CONFIGID                           AS Config,
      dim.INVENTSIZEID                       AS Ebat,
      dim.INVENTCOLORID                      AS Renk,
      dim.INVENTBATCHID                      AS Parti,
      dim.INVENTSERIALID                     AS Seri,
      SUM(CASE WHEN T.QTY > 0 THEN T.QTY ELSE 0 END)                                          AS GirisQty,
      SUM(CASE WHEN T.QTY > 0 THEN (T.COSTAMOUNTPOSTED + T.COSTAMOUNTADJUSTMENT) ELSE 0 END)   AS GirisTutar,
      SUM(CASE WHEN T.QTY < 0 THEN T.QTY ELSE 0 END)                                          AS CikisQty,
      SUM(CASE WHEN T.QTY < 0 THEN (T.COSTAMOUNTPOSTED + T.COSTAMOUNTADJUSTMENT) ELSE 0 END)   AS CikisTutar,
      SUM(T.QTY)                                                                                AS NetQty,
      SUM(T.COSTAMOUNTPOSTED + T.COSTAMOUNTADJUSTMENT)                                          AS NetTutar,
      MIN(T.VOUCHER)                        AS Fis,
      MIN(ISNULL(T.DATEPHYSICAL, T.DATEFINANCIAL)) AS Tarih
    FROM INVENTTRANS T
    JOIN INVENTTRANSORIGIN ori ON ori.RECID = T.INVENTTRANSORIGIN AND ori.DATAAREAID = T.DATAAREAID AND ori.PARTITION = T.PARTITION
    JOIN INVENTDIM dim ON dim.INVENTDIMID = T.INVENTDIMID AND dim.DATAAREAID = T.DATAAREAID AND dim.PARTITION = T.PARTITION
    LEFT JOIN INVENTTABLE M ON M.ITEMID = T.ITEMID AND M.DATAAREAID = T.DATAAREAID AND M.PARTITION = T.PARTITION
    WHERE ISNULL(T.DATEPHYSICAL, T.DATEFINANCIAL) BETWEEN '${baslangic}' AND '${bitis}' ${cw}
    GROUP BY
      T.ITEMID, M.NAMEALIAS, ISNULL(M.ERP_ITEMGROUPID,''),
      ori.REFERENCECATEGORY,
      dim.INVENTLOCATIONID, dim.CONFIGID, dim.INVENTSIZEID,
      dim.INVENTCOLORID, dim.INVENTBATCHID, dim.INVENTSERIALID
    ORDER BY T.ITEMID, ori.REFERENCECATEGORY`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);

    // RefCat açıklamaları
    const refMap = {
      0:'Satış', 1:'Satınalma', 2:'SatışFatura', 3:'SatınAlmaFatura',
      4:'Transfer', 5:'Hareket', 6:'Sayım', 7:'BOM', 8:'Üretim',
      9:'ÜretimSatır', 10:'TüretilmişÜrün', 11:'Proje', 12:'ÜretimBant',
      14:'Diğer', 17:'Kanban', 20:'StokKapat', 26:'SatışSipTeslim'
    };

    const data = rows.map(r => {
      const gBF = r.GirisQty > 0 ? Math.round((r.GirisTutar / r.GirisQty) * 100) / 100 : 0;
      const cBF = r.CikisQty < 0 ? Math.round((r.CikisTutar / r.CikisQty) * 100) / 100 : 0;
      const bfFark = gBF && cBF ? Math.round((gBF - cBF) * 100) / 100 : 0;
      return {
        ...r,
        PostingTip: refMap[r.RefCat] || ('Tip-' + r.RefCat),
        GirisBF: gBF,
        CikisBF: cBF,
        BFFark: bfFark
      };
    });
    ok(res, { rows: data, toplam: data.length, donem: baslangic + ' / ' + bitis });
  });
});

// ═══════════════════════════════════════════════════════
// KK ÜRETİM MALİYET KONTROL
// RefCat 2=Üretim(mamul giriş), 8=ÜretimSatır(hammadde çıkış)
// ?tip=net    → Emir bazında net≠0
// ?tip=sifir  → Maliyetsiz satırlar (tutar=0, qty≠0)
// ?tip=all    → Hepsi
// ═══════════════════════════════════════════════════════
route('/api/kkUretimKontrol', (req, res, f) => {
  const company = f.company || 'KK';
  const cw = f.company && f.company !== 'DAT' ? `AND T.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const baslangic = f.baslangic || '2026-01-01';
  const bitis     = f.bitis     || '2026-01-31';

  const q = `
    SELECT
      ori.REFERENCEID       AS ProdId,
      ori.REFERENCECATEGORY AS RefCat,
      T.ITEMID            AS ItemId,
      M.ITEMNAME          AS ItemName,
      ISNULL(M.ERP_ITEMGROUPID,'') AS ItemGroup,
      dim.INVENTLOCATIONID  AS Ambar,
      dim.CONFIGID          AS Config,
      dim.INVENTSIZEID      AS Ebat,
      dim.INVENTCOLORID     AS Renk,
      dim.INVENTBATCHID     AS Parti,
      SUM(T.QTY)          AS Qty,
      SUM(T.COSTAMOUNTPOSTED + T.COSTAMOUNTADJUSTMENT) AS Tutar,
      SUM(T.COSTAMOUNTPOSTED) AS Posted,
      SUM(T.COSTAMOUNTADJUSTMENT) AS Adj,
      MIN(T.VOUCHER)      AS Fis,
      MIN(ISNULL(T.DATEPHYSICAL, T.DATEFINANCIAL)) AS Tarih
    FROM INVENTTRANS T
    JOIN INVENTTRANSORIGIN ori ON ori.RECID = T.INVENTTRANSORIGIN AND ori.DATAAREAID = T.DATAAREAID AND ori.PARTITION = T.PARTITION
    JOIN INVENTDIM dim ON dim.INVENTDIMID = T.INVENTDIMID AND dim.DATAAREAID = T.DATAAREAID AND dim.PARTITION = T.PARTITION
    LEFT JOIN INVENTTABLE M ON M.ITEMID = T.ITEMID AND M.DATAAREAID = T.DATAAREAID AND M.PARTITION = T.PARTITION
    WHERE ori.REFERENCECATEGORY IN (2, 8)
      AND ISNULL(T.DATEPHYSICAL, T.DATEFINANCIAL) BETWEEN '${baslangic}' AND '${bitis}' ${cw}
    GROUP BY ori.REFERENCEID, ori.REFERENCECATEGORY, T.ITEMID, M.NAMEALIAS,
      ISNULL(M.ERP_ITEMGROUPID,''), dim.INVENTLOCATIONID, dim.CONFIGID, dim.INVENTSIZEID,
      dim.INVENTCOLORID, dim.INVENTBATCHID
    ORDER BY ori.REFERENCEID, ori.REFERENCECATEGORY`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);

    const tip = (f.esl && f.esl.esl_tip) || 'all';

    // Her satıra PostingTip ve BF ekle
    const all = rows.map(r => ({
      ...r,
      PostingTip: r.RefCat === 2 ? 'Üretim' : 'ÜretimSatır',
      BF: r.Qty !== 0 ? Math.round(Math.abs(r.Tutar / r.Qty) * 100) / 100 : 0,
      Maliyetsiz: (Math.abs(r.Tutar) < 0.01 && Math.abs(r.Qty) > 0.01) ? 1 : 0
    }));

    // Emir bazında net tutar hesapla
    const emirNet = {};
    all.forEach(r => {
      if (!emirNet[r.ProdId]) emirNet[r.ProdId] = 0;
      emirNet[r.ProdId] += r.Tutar;
    });

    // EmirNet ekle
    all.forEach(r => {
      r.EmirNet = Math.round(emirNet[r.ProdId] * 100) / 100;
    });

    let result;
    if (tip === 'net') {
      result = all.filter(r => Math.abs(r.EmirNet) > 0.01);
    } else if (tip === 'sifir') {
      result = all.filter(r => r.Maliyetsiz === 1);
    } else {
      result = all;
    }

    // Özet
    const ozet = {
      toplamEmir: new Set(all.map(r => r.ProdId)).size,
      sorunluEmir: new Set(all.filter(r => Math.abs(r.EmirNet) > 0.01).map(r => r.ProdId)).size,
      maliyetsizSatir: all.filter(r => r.Maliyetsiz === 1).length,
      maliyetsizEmir: new Set(all.filter(r => r.Maliyetsiz === 1).map(r => r.ProdId)).size
    };

    ok(res, { rows: result, toplam: result.length, ozet, donem: baslangic + ' / ' + bitis });
  });
});

// ═══════════════════════════════════════════════════════
// KK REÇETE BAZLI MALİYET — Üretim emri + BOM satırları
// ═══════════════════════════════════════════════════════
route('/api/kkReceteMaliyet', (req, res, f) => {
  const company = f.company || 'KK';
  const cw = f.company && f.company !== 'DAT' ? `AND p.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const baslangic = f.baslangic || '2026-01-01';
  const bitis     = f.bitis     || '2026-01-31';

  const q = `
    SELECT
      PRODID,
      MAMULID,
      MAMULADI,
      PRODGROUPID,
      PRODSTATUS,
      PLANLANANMIKTAR,
      URETILENQTY,
      INVENTSITEID,
      INVENTLOCATIONID,
      CONFIGID,
      INVENTSIZEID,
      INVENTCOLORID,
      HAMMADDE_ITEMID,
      HAMMADDE_ADI,
      HAMMADDE_GRUBU,
      SUM(PLANLANAN_MIKTAR)   AS PlanQty,
      SUM(GERCEKLESEN_MIKTAR) AS GercekQty,
      SUM(MALIYET_TL)         AS MaliyetTL,
      HAM_AMBAR,
      HAM_PARTI,
      MIN(TUKETIM_TARIHI)     AS Tarih,
      MIN(TUKETIM_FISNO)      AS Fis,
      p.DATAAREAID
    FROM ERP_BI_URETIMMALIYETI p
    WHERE 1=1 ${cw}
      AND ISNULL(TUKETIM_TARIHI, FINISHEDDATE) BETWEEN '${baslangic}' AND '${bitis}'
    GROUP BY PRODID, MAMULID, MAMULADI, PRODGROUPID, PRODSTATUS,
      PLANLANANMIKTAR, URETILENQTY,
      INVENTSITEID, INVENTLOCATIONID, CONFIGID, INVENTSIZEID, INVENTCOLORID,
      HAMMADDE_ITEMID, HAMMADDE_ADI, HAMMADDE_GRUBU,
      HAM_AMBAR, HAM_PARTI, p.DATAAREAID
    ORDER BY PRODID, HAMMADDE_ITEMID`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);

    // Üretim emri bazında mamul maliyeti hesapla
    const emirMap = {};
    rows.forEach(r => {
      if (!emirMap[r.PRODID]) {
        emirMap[r.PRODID] = {
          mamulId: r.MAMULID, mamulAdi: r.MAMULADI,
          prodGrup: r.PRODGROUPID, status: r.PRODSTATUS,
          planQty: r.PLANLANANMIKTAR, uretQty: r.URETILENQTY,
          site: r.INVENTSITEID, ambar: r.INVENTLOCATIONID,
          config: r.CONFIGID, ebat: r.INVENTSIZEID, renk: r.INVENTCOLORID,
          topMaliyet: 0, satirlar: []
        };
      }
      const mal = r.MaliyetTL || 0;
      emirMap[r.PRODID].topMaliyet += mal;
    });

    // Her satıra emir bilgisi ekle
    const data = rows.map(r => {
      const em = emirMap[r.PRODID];
      const hamBF = r.GercekQty ? Math.round(((r.MaliyetTL || 0) / Math.abs(r.GercekQty)) * 100) / 100 : 0;
      const mamulBF = em.uretQty ? Math.round((em.topMaliyet / em.uretQty) * 100) / 100 : 0;
      const sapmaPct = r.PlanQty ? Math.round(((r.GercekQty - r.PlanQty) / r.PlanQty) * 10000) / 100 : 0;
      return {
        ProdId: r.PRODID,
        MamulId: r.MAMULID,
        MamulAdi: r.MAMULADI,
        ProdGrup: r.PRODGROUPID,
        Status: r.PRODSTATUS,
        UretQty: r.URETILENQTY,
        PlanQty: r.PLANLANANMIKTAR,
        HamId: r.HAMMADDE_ITEMID,
        HamAdi: r.HAMMADDE_ADI,
        HamGrup: r.HAMMADDE_GRUBU,
        HamAmbar: r.HAM_AMBAR,
        Parti: r.HAM_PARTI,
        Config: r.CONFIGID || '',
        Ebat: r.INVENTSIZEID || '',
        Renk: r.INVENTCOLORID || '',
        BomPlan: r.PlanQty || 0,
        BomGercek: r.GercekQty || 0,
        SapmaPct: sapmaPct,
        HamMaliyet: r.MaliyetTL || 0,
        HamBF: hamBF,
        EmirTopMaliyet: Math.round(em.topMaliyet * 100) / 100,
        MamulBF: mamulBF,
        Maliyetsiz: (Math.abs(r.MaliyetTL || 0) < 0.01 && Math.abs(r.GercekQty || 0) > 0.01) ? 1 : 0,
        Tarih: r.Tarih,
        Fis: r.Fis
      };
    });

    // Özet
    const ozet = {
      toplamEmir: Object.keys(emirMap).length,
      toplamSatir: data.length,
      maliyetsiz: data.filter(r => r.Maliyetsiz).length,
      sapmaVar: data.filter(r => Math.abs(r.SapmaPct) > 5).length,
      topMaliyet: Math.round(Object.values(emirMap).reduce((s, e) => s + e.topMaliyet, 0) * 100) / 100
    };

    ok(res, { rows: data, toplam: data.length, ozet, donem: baslangic + ' / ' + bitis });
  });
});

// ═══════════════════════════════════════════════════════
// KK SATIŞ KARLILIK — Fatura bazlı satış vs maliyet
// ═══════════════════════════════════════════════════════
route('/api/kkSatisKarlilik', (req, res, f) => {
  const company = f.company || 'KK';
  const cw = f.company && f.company !== 'DAT' ? `AND sk.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const baslangic = f.baslangic || '2026-01-01';
  const bitis     = f.bitis     || '2026-01-31';

  const q = `
    SELECT
      sk.INVOICEDATE   AS Tarih,
      sk.INVOICEID     AS FaturaNo,
      sk.SALESID       AS SiparisNo,
      sk.INVOICEACCOUNT AS MusteriKod,
      sk.CUSTNAME      AS MusteriAdi,
      sk.ITEMID        AS ItemId,
      sk.ITEMNAME      AS ItemName,
      sk.ITEMGROUPID   AS ItemGroup,
      sk.SALESGROUP    AS SatisGrup,
      sk.CONFIGID      AS Config,
      sk.INVENTSIZEID  AS Ebat,
      sk.INVENTCOLORID AS Renk,
      sk.QTY           AS Qty,
      sk.SALESPRICE    AS BirimFiyat,
      sk.SATISTUTAR_TL AS SatisTutar,
      sk.KDVTUTAR_TL   AS KdvTutar,
      sk.BIRIM_MALIYET AS MaliyetBirim,
      sk.MALIYET_BIRIM AS MaliyetUnit,
      sk.TOPLAM_MALIYET_TL AS TopMaliyet,
      sk.BRUTKAR_TL    AS BrutKar,
      sk.BRUTKAR_MARJI  AS KarMarji,
      sk.COSTINGTYPE
    FROM ERP_BI_SATIS_KARLILIK sk
    WHERE 1=1 ${cw}
      AND sk.INVOICEDATE BETWEEN '${baslangic}' AND '${bitis}'
    ORDER BY sk.INVOICEDATE, sk.INVOICEID`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    const sifirMaliyet = rows.filter(r => Math.abs(r.TopMaliyet || 0) < 0.01 && Math.abs(r.Qty || 0) > 0.01);
    const ozet = {
      toplamFatura: new Set(rows.map(r => r.FaturaNo)).size,
      toplamSatir: rows.length,
      topSatis: Math.round(rows.reduce((s, r) => s + (r.SatisTutar || 0), 0) * 100) / 100,
      topMaliyet: Math.round(rows.reduce((s, r) => s + (r.TopMaliyet || 0), 0) * 100) / 100,
      topKar: Math.round(rows.reduce((s, r) => s + (r.BrutKar || 0), 0) * 100) / 100,
      sifirMaliyet: sifirMaliyet.length
    };
    ok(res, { rows, toplam: rows.length, ozet, donem: baslangic + ' / ' + bitis });
  });
});

// ═══════════════════════════════════════════════════════
// KK MADDE MALİYET — InventItemPrice aktif maliyet listesi
// ═══════════════════════════════════════════════════════
route('/api/kkMaddeMaliyet', (req, res, f) => {
  const company = f.company || 'KK';
  const cw = f.company && f.company !== 'DAT' ? `AND m.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';

  const q = `
    SELECT
      m.ITEMID         AS ItemId,
      m.ITEMNAME       AS ItemName,
      m.ITEMGROUPID    AS ItemGroup,
      m.ITEMGROUPNAME  AS GroupName,
      m.PRODGROUPID    AS ProdGrup,
      m.PRICETYPE      AS FiyatTip,
      m.COSTINGTYPE    AS MaliyetTip,
      m.PRICE          AS Fiyat,
      m.PRICEUNIT      AS FiyatBirim,
      m.BIRIM_MALIYET  AS BirimMaliyet,
      m.UNITID         AS Birim,
      m.ACTIVATIONDATE AS AktifTarih,
      m.CONFIGID       AS Config,
      m.INVENTSIZEID   AS Ebat,
      m.INVENTCOLORID  AS Renk,
      m.INVENTSITEID   AS Tesis
    FROM ERP_BI_MALIYET m
    WHERE m.PRICETYPE = 1 ${cw}
    ORDER BY m.ITEMID, m.ACTIVATIONDATE DESC`;

  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    const sifir = rows.filter(r => (r.BirimMaliyet || 0) < 0.01);
    const ozet = {
      toplamMadde: new Set(rows.map(r => r.ItemId)).size,
      toplamKayit: rows.length,
      sifirMaliyet: sifir.length,
      sifirMadde: new Set(sifir.map(r => r.ItemId)).size
    };
    ok(res, { rows, toplam: rows.length, ozet });
  });
});

// ═══════════════════════════════════════════════════════
// KK SIFIR MALİYET — Tüm kaynaklardan sıfır bedelli olanlar
// + InventItemPrice'tan hesaplanmış maliyet önerisi
// ═══════════════════════════════════════════════════════
route('/api/kkSifirMaliyet', (req, res, f) => {
  const company = f.company || 'KK';
  const cw = f.company && f.company !== 'DAT' ? `AND T.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const baslangic = f.baslangic || '2026-01-01';
  const bitis     = f.bitis     || '2026-01-31';

  // 1. Sıfır maliyetli hareketler
  const q1 = `
    SELECT
      ori.REFERENCEID      AS RefId,
      ori.REFERENCECATEGORY AS RefCat,
      T.ITEMID           AS ItemId,
      M.NAMEALIAS         AS ItemName,
      ISNULL(M.ERP_ITEMGROUPID,'') AS ItemGroup,
      dim.INVENTLOCATIONID AS Ambar,
      dim.CONFIGID         AS Config,
      dim.INVENTSIZEID     AS Ebat,
      dim.INVENTCOLORID    AS Renk,
      dim.INVENTBATCHID    AS Parti,
      SUM(T.QTY)         AS Qty,
      SUM(T.COSTAMOUNTPOSTED + T.COSTAMOUNTADJUSTMENT) AS Tutar,
      MIN(T.VOUCHER)     AS Fis,
      MIN(ISNULL(T.DATEPHYSICAL, T.DATEFINANCIAL)) AS Tarih
    FROM INVENTTRANS T
    JOIN INVENTTRANSORIGIN ori ON ori.RECID = T.INVENTTRANSORIGIN AND ori.DATAAREAID = T.DATAAREAID AND ori.PARTITION = T.PARTITION
    JOIN INVENTDIM dim ON dim.INVENTDIMID = T.INVENTDIMID AND dim.DATAAREAID = T.DATAAREAID AND dim.PARTITION = T.PARTITION
    LEFT JOIN INVENTTABLE M ON M.ITEMID = T.ITEMID AND M.DATAAREAID = T.DATAAREAID AND M.PARTITION = T.PARTITION
    WHERE ISNULL(T.DATEPHYSICAL, T.DATEFINANCIAL) BETWEEN '${baslangic}' AND '${bitis}' ${cw}
      AND ABS(T.COSTAMOUNTPOSTED + T.COSTAMOUNTADJUSTMENT) < 0.01
      AND ABS(T.QTY) > 0.01
    GROUP BY T.REFERENCEID, T.REFERENCECATEGORY, T.ITEMID, M.ITEMNAME,
      ISNULL(M.ITEMGROUPID,''), T.INVENTLOCATIONID, T.CONFIGID, T.INVENTSIZEID,
      T.INVENTCOLORID, T.INVENTBATCHID
    ORDER BY T.ITEMID`;

  // 2. Aktif maliyet fiyatları (öneri için)
  const cw2 = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const q2 = `
    SELECT ITEMID, MAX(BIRIM_MALIYET) AS SonMaliyet
    FROM ERP_BI_MALIYET
    WHERE PRICETYPE = 1 ${cw2}
    GROUP BY ITEMID`;

  query(q1, [], (e1, sifirler) => {
    if (e1) return err(res, e1);
    query(q2, [], (e2, fiyatlar) => {
      if (e2) return err(res, e2);

      const fiyatMap = {};
      fiyatlar.forEach(f => { fiyatMap[f.ITEMID] = f.SonMaliyet; });

      const refMap = {
        0:'Satış',1:'Satınalma',2:'Üretim',3:'SatınAlmaFatura',
        4:'Transfer',5:'Hareket',6:'Sayım',7:'BOM',8:'ÜretimSatır',
        9:'ÜretimSatır',10:'TüretilmişÜrün',12:'ÜretimBant',26:'Sevk'
      };

      const data = sifirler.map(r => {
        const oneriMaliyet = fiyatMap[r.ItemId] || 0;
        const oneriTutar = Math.round(Math.abs(r.Qty) * oneriMaliyet * 100) / 100;
        return {
          ...r,
          PostingTip: refMap[r.RefCat] || ('Tip-' + r.RefCat),
          OneriMaliyet: oneriMaliyet,
          OneriTutar: oneriTutar,
          Kaynak: oneriMaliyet > 0 ? 'InventItemPrice' : 'YOK'
        };
      });

      const ozet = {
        toplamSatir: data.length,
        toplamMadde: new Set(data.map(r => r.ItemId)).size,
        oneriVar: data.filter(r => r.OneriMaliyet > 0).length,
        oneriYok: data.filter(r => r.OneriMaliyet === 0).length,
        topOneriTutar: Math.round(data.reduce((s, r) => s + r.OneriTutar, 0) * 100) / 100
      };

      ok(res, { rows: data, toplam: data.length, ozet, donem: baslangic + ' / ' + bitis });
    });
  });
});

// ═══════════════════════════════════════════════════════
// EKSİK RAPOR ENDPOINT'LERİ (D365 dönüşümü için eklendi)
// Aynı desen: route('/api/x',(req,res,f)=>{ ... query(...) ... ok(res,{rows}) })
// ═══════════════════════════════════════════════════════

// MADDE KARTLARI — ERP_BI_MADDEKARTI
route('/api/madde', (req, res, f) => {
  const cw  = f.company && f.company !== 'DAT' ? `AND M.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const grp = f.maddeGr ? `AND M.ITEMGROUPID = '${f.maddeGr}'` : '';
  const q = `
    SELECT TOP ${f.limit}
      M.ITEMID, M.ITEMNAME, M.ITEMGROUPID
    FROM ERP_BI_MADDEKARTI M
    WHERE 1=1 ${cw} ${grp}
    GROUP BY M.ITEMID, M.ITEMNAME, M.ITEMGROUPID
    ORDER BY M.ITEMID`;
  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      itemId : r.ITEMID      || '',
      isim   : r.ITEMNAME    || '',
      grup   : r.ITEMGROUPID || ''
    }))});
  });
});

// NEGATİF STOK — ERP_BI_INVENTTRANS (bakiye < 0)
route('/api/negatifStok', (req, res, f) => {
  const cw   = f.company && f.company !== 'DAT' ? `AND T.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const depo = f.depo ? `AND T.INVENTLOCATIONID = '${f.depo}'` : '';
  const q = `
    SELECT TOP ${f.limit}
      T.ITEMID, M.ITEMNAME, M.ITEMGROUPID,
      T.INVENTSITEID AS tesis, T.INVENTLOCATIONID AS depo,
      SUM(T.QTY) AS miktar, SUM(T.COSTAMOUNTPOSTED) AS deger
    FROM ERP_BI_INVENTTRANS T
    LEFT JOIN ERP_BI_MADDEKARTI M ON M.ITEMID = T.ITEMID AND M.DATAAREAID = T.DATAAREAID
    WHERE 1=1 ${cw} ${depo}
    GROUP BY T.ITEMID, M.ITEMNAME, M.ITEMGROUPID, T.INVENTSITEID, T.INVENTLOCATIONID
    HAVING SUM(T.QTY) < 0
    ORDER BY SUM(T.QTY)`;
  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      itemId : r.ITEMID      || '',
      isim   : r.ITEMNAME    || '',
      grup   : r.ITEMGROUPID || '',
      tesis  : r.tesis       || '',
      depo   : r.depo        || '',
      miktar : parseFloat(r.miktar) || 0,
      deger  : parseFloat(r.deger)  || 0
    }))});
  });
});

// MUHASEBE DETAY — ERP_BI_LEDGERTRANS (satır bazlı, gruplamasız)
route('/api/muhasebeDetay', (req, res, f) => {
  const cw  = companyWhere(f.company, 'L');
  const aw  = ayWhere(f, 'L');
  const acc = f.hesap ? `AND L.MAINACCOUNTNUM LIKE '${f.hesap}%'` : '';
  const q = `
    SELECT TOP ${f.limit}
      L.MAINACCOUNTNUM, H.ACCOUNTNAME, L.TRANSDATE, L.AMOUNTMST
    FROM ERP_BI_LEDGERTRANS L
    LEFT JOIN ERP_BI_HESAPPLANI H ON H.MAINACCOUNTID = L.MAINACCOUNTNUM
    WHERE 1=1 ${cw} ${aw} ${acc}
    ORDER BY L.TRANSDATE DESC, L.MAINACCOUNTNUM`;
  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap  : r.MAINACCOUNTNUM,
      isim   : r.ACCOUNTNAME || '',
      tarih  : r.TRANSDATE,
      tutar  : parseFloat(r.AMOUNTMST) || 0
    }))});
  });
});

// ÇEK / VADE — ERP_BI_BORC (vade tarihine göre açık tutarlar)
route('/api/cekVade', (req, res, f) => {
  const cw = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const q = `
    SELECT TOP ${f.limit}
      ACCOUNTNUM, VENDNAME, TRANSDATE, DUEDATE, OPENAMOUNTMST,
      DATEDIFF(DAY, GETDATE(), DUEDATE) AS kalanGun
    FROM ERP_BI_BORC
    WHERE (CLOSED IS NULL OR CLOSED <= '1900-01-02')
      AND OPENAMOUNTMST <> 0 AND DUEDATE IS NOT NULL
      ${cw}
    ORDER BY DUEDATE`;
  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap   : r.ACCOUNTNUM,
      isim    : r.VENDNAME || '',
      tarih   : r.TRANSDATE,
      vade    : r.DUEDATE,
      tutar   : Math.abs(parseFloat(r.OPENAMOUNTMST) || 0),
      kalanGun: parseInt(r.kalanGun) || 0
    }))});
  });
});

// MÜŞTERİ KÂRLILIK — ERP_BI_SATISFATURA (müşteri bazlı ciro/miktar)
route('/api/musteriKar', (req, res, f) => {
  const cw = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(INVOICEDATE)=${d.yil} AND MONTH(INVOICEDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(INVOICEDATE) = ${f.yil}`;
  const q = `
    SELECT TOP ${f.limit}
      INVOICEACCOUNT, NAME,
      SUM(LINEAMOUNTMST) AS ciro,
      SUM(QTY) AS miktar,
      COUNT(DISTINCT INVOICEID) AS faturaAdedi
    FROM ERP_BI_SATISFATURA
    WHERE INVOICEDATE IS NOT NULL ${cw} ${aw}
    GROUP BY INVOICEACCOUNT, NAME
    ORDER BY ciro DESC`;
  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      musteri : r.INVOICEACCOUNT || '',
      isim    : r.NAME || '',
      ciro    : parseFloat(r.ciro)   || 0,
      miktar  : parseFloat(r.miktar) || 0,
      fatura  : parseInt(r.faturaAdedi) || 0
    }))});
  });
});

// ÜRETİM VERİMLİLİĞİ — ERP_BI_URETIMEMRI (planlanan vs üretilen)
route('/api/uretimVerim', (req, res, f) => {
  const cw  = f.company && f.company !== 'DAT' ? `AND DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const grp = f.maddeGr ? `AND PRODGROUPID = '${f.maddeGr}'` : '';
  const q = `
    SELECT TOP ${f.limit}
      PRODID, ITEMID, ITEMNAME, PRODGROUPID,
      QTYCALC, PRODUCEDQTY,
      CASE WHEN QTYCALC > 0 THEN CAST(PRODUCEDQTY*100.0/QTYCALC AS DECIMAL(9,2)) ELSE 0 END AS verim
    FROM ERP_BI_URETIMEMRI
    WHERE PRODSTATUS NOT IN (5, 8) AND QTYCALC > 0
      ${cw} ${grp}
    ORDER BY verim`;
  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      prodId    : r.PRODID,
      itemId    : r.ITEMID || '',
      isim      : r.ITEMNAME || '',
      grupId    : r.PRODGROUPID || '',
      planlanan : parseFloat(r.QTYCALC)     || 0,
      uretilen  : parseFloat(r.PRODUCEDQTY) || 0,
      verim     : parseFloat(r.verim)       || 0
    }))});
  });
});

// FİİLİ MALİ TABLOLAR — ERP_BI_MIZAN_DETAY (HTA: erbi_Fiili.hta)
route('/api/fiili', (req, res, f) => {
  const cw  = f.company && f.company !== 'DAT' ? `AND SIRKETKODU = '${f.company}'` : '';
  const acc = f.hesap ? `AND HESAPKODU LIKE '${f.hesap}%'` : '';
  const q = `SELECT TOP ${f.limit} * FROM ERP_BI_MIZAN_DETAY WHERE 1=1 ${cw} ${acc}`;
  query(q, [], (e, rows) => { if (e) return err(res, e); ok(res, { rows: rows || [] }); });
});

// KONSOLİDE YÖNETİM RAPORU — ERP_BI_KONSOLIDE_OZET (HTA: erpbi_Konsolide.hta)
route('/api/konsolide', (req, res, f) => {
  // Konsolide motoru ERP_BI_MIZAN_DETAY hesap-kodu detayını ister (5 şirket); HTA sqlMizanDetay() ile birebir
  const yil = f.yil || new Date().getFullYear();
  const q = `
    SELECT TOP ${f.limit}
      SIRKETKODU, DONEM, HESAPKODU, HESAP_SINIF, HESAP_GRUP3, HESAP_GRUP5, HESAPADI,
      SUM(NETBAKIYE) AS NETBAKIYE
    FROM ERP_BI_MIZAN_DETAY
    WHERE SIRKETKODU IN ('KK','NT','YTY','ELM','NFGE')
      AND LEFT(DONEM,4) = '${yil}'
    GROUP BY SIRKETKODU, DONEM, HESAPKODU, HESAP_SINIF, HESAP_GRUP3, HESAP_GRUP5, HESAPADI
    ORDER BY SIRKETKODU, DONEM, HESAPKODU`;
  query(q, [], (e, rows) => { if (e) return err(res, e); ok(res, { rows: rows || [] }); });
});

// STOK GÖSTERGELERİ — SDH (devir hızı) / STS (tutma süresi) — ERP_BI_INVENTTRANS
route('/api/stokGosterge', (req, res, f) => {
  const cw  = f.company && f.company !== 'DAT' ? `AND T.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const grp = f.maddeGr ? `AND M.ITEMGROUPID = '${f.maddeGr}'` : '';
  const q = `
    SELECT TOP ${f.limit}
      M.ITEMGROUPID AS stokGrup,
      COUNT(DISTINCT T.ITEMID) AS kalemSayisi,
      SUM(CASE WHEN T.STATUSISSUE >= 1 THEN ABS(T.COSTAMOUNTPOSTED) ELSE 0 END) AS satisMaliyet,
      AVG(ABS(T.COSTAMOUNTPOSTED)) AS ortStokDeger
    FROM ERP_BI_INVENTTRANS T
    LEFT JOIN ERP_BI_MADDEKARTI M ON M.ITEMID = T.ITEMID AND M.DATAAREAID = T.DATAAREAID
    WHERE 1=1 ${cw} ${grp}
    GROUP BY M.ITEMGROUPID
    HAVING AVG(ABS(T.COSTAMOUNTPOSTED)) > 0
    ORDER BY satisMaliyet DESC`;
  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => {
      const sm=parseFloat(r.satisMaliyet)||0, os=parseFloat(r.ortStokDeger)||0;
      const sdh = os>0 ? sm/os : 0;
      return {
        stokGrup    : r.stokGrup || '(grupsuz)',
        kalemSayisi : parseInt(r.kalemSayisi) || 0,
        satisMaliyet: sm,
        ortStokDeger: os,
        SDH         : Math.round(sdh*100)/100,
        STS_gun     : sdh>0 ? Math.round(365/sdh) : 0
      };
    })});
  });
});

// ZARAR EDEN SATIŞLAR — ERP_BI_SATIS_KARLILIK (BrutKar < 0)
route('/api/zararSatis', (req, res, f) => {
  const cw  = f.company && f.company !== 'DAT' ? `AND sk.DATAAREAID = '${COMPANY_MAP[f.company]?.code}'` : '';
  const aw  = f.aylarList?.length > 0
    ? `AND (${f.aylarList.map(d=>`(YEAR(sk.INVOICEDATE)=${d.yil} AND MONTH(sk.INVOICEDATE)=${d.ay})`).join(' OR ')})`
    : `AND YEAR(sk.INVOICEDATE) = ${f.yil}`;
  const mus = f.musteri ? `AND sk.INVOICEACCOUNT = '${f.musteri}'` : '';
  const q = `
    SELECT TOP ${f.limit}
      sk.INVOICEDATE AS tarih, sk.INVOICEACCOUNT AS musteri, sk.CUSTNAME AS musteriAdi,
      sk.ITEMID AS madde, sk.ITEMNAME AS maddeAdi, sk.ITEMGROUPID AS grup,
      sk.QTY AS miktar, sk.SATISTUTAR_TL AS satisTutar, sk.TOPLAM_MALIYET_TL AS maliyet,
      sk.BRUTKAR_TL AS brutKar, sk.BRUTKAR_MARJI AS marj
    FROM ERP_BI_SATIS_KARLILIK sk
    WHERE sk.BRUTKAR_TL < 0 ${cw} ${aw} ${mus}
    ORDER BY sk.BRUTKAR_TL`;
  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      tarih      : r.tarih,
      musteri    : r.musteri || '',
      musteriAdi : r.musteriAdi || '',
      madde      : r.madde || '',
      maddeAdi   : r.maddeAdi || '',
      grup       : r.grup || '',
      miktar     : parseFloat(r.miktar) || 0,
      satisTutar : parseFloat(r.satisTutar) || 0,
      maliyet    : parseFloat(r.maliyet) || 0,
      brutKar    : parseFloat(r.brutKar) || 0,
      marj       : parseFloat(r.marj) || 0
    }))});
  });
});

// GİDER DAĞILIMI — ERP_BI_LEDGERTRANS (gider hesapları 6xx/7xx, boyut bazlı)
route('/api/giderDagilim', (req, res, f) => {
  const cw  = companyWhere(f.company, 'L');
  const aw  = ayWhere(f, 'L');
  const acc = f.hesap ? `AND L.MAINACCOUNTNUM LIKE '${f.hesap}%'` : `AND (L.MAINACCOUNTNUM LIKE '6%' OR L.MAINACCOUNTNUM LIKE '7%')`;
  const d1  = f.dim1 ? `AND L.DIMENSION = '${f.dim1}'`  : '';
  const d2  = f.dim2 ? `AND L.DIMENSION2_ = '${f.dim2}'` : '';
  const q = `
    SELECT TOP ${f.limit}
      L.MAINACCOUNTNUM AS hesap, H.ACCOUNTNAME AS hesapAdi,
      L.DIMENSION AS boyut1, L.DIMENSION2_ AS boyut2,
      SUM(L.AMOUNTMST) AS tutar
    FROM ERP_BI_LEDGERTRANS L
    LEFT JOIN ERP_BI_HESAPPLANI H ON H.MAINACCOUNTID = L.MAINACCOUNTNUM
    WHERE 1=1 ${cw} ${aw} ${acc} ${d1} ${d2}
    GROUP BY L.MAINACCOUNTNUM, H.ACCOUNTNAME, L.DIMENSION, L.DIMENSION2_
    ORDER BY SUM(L.AMOUNTMST) DESC`;
  query(q, [], (e, rows) => {
    if (e) return err(res, e);
    ok(res, { rows: rows.map(r => ({
      hesap    : r.hesap,
      hesapAdi : r.hesapAdi || '',
      boyut1   : r.boyut1 || '',
      boyut2   : r.boyut2 || '',
      tutar    : parseFloat(r.tutar) || 0
    }))});
  });
});

// ═══════════════════════════════════════════════════════
const server = http.createServer((req, res) => {
  // OPTIONS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, HEADERS);
    return res.end();
  }

  // ── KILL SWITCH ────────────────────────────────────
  if (!SECURITY.ACTIVE) {
    res.writeHead(503, HEADERS);
    return res.end(JSON.stringify({ error: 'Sistem bakımda. Lütfen yöneticinize başvurun.' }));
  }

  // ── RATE LIMIT ─────────────────────────────────────
  const clientIP = req.socket.remoteAddress || 'unknown';
  if (!checkRate(clientIP)) {
    res.writeHead(429, HEADERS);
    return res.end(JSON.stringify({ error: 'Çok fazla istek. Lütfen bekleyin.' }));
  }

  let pathname, queryObj;
  try {
    const u = new URL(req.url, 'http://localhost');
    pathname = u.pathname;
    const qs = {};
    u.searchParams.forEach((v, k) => { qs[k] = v; });
    queryObj = qs;
  } catch(e) {
    return notFound(res);
  }

  // ── LOGIN ENDPOINT ─────────────────────────────────
  if (pathname === '/api/login' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const user = SECURITY.USERS[data.user];
        if (!user || user.pass !== data.pass) {
          res.writeHead(401, HEADERS);
          return res.end(JSON.stringify({ error: 'Geçersiz kullanıcı adı veya şifre' }));
        }
        const token = jwtSign({ user: data.user, role: user.role });
        res.writeHead(200, HEADERS);
        res.end(JSON.stringify({ token, role: user.role, expire: '24 saat' }));
      } catch(e) {
        res.writeHead(400, HEADERS);
        res.end(JSON.stringify({ error: 'Geçersiz istek' }));
      }
    });
    return;
  }

  // ── ADMIN: Kill Switch ─────────────────────────────
  if (pathname === '/api/admin/kill' && req.method === 'POST') {
    const auth = authenticate(req);
    if (!auth.ok || auth.role !== 'admin') {
      res.writeHead(403, HEADERS);
      return res.end(JSON.stringify({ error: 'Yetki yok' }));
    }
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      const data = JSON.parse(body || '{}');
      SECURITY.ACTIVE = data.active !== false;
      res.writeHead(200, HEADERS);
      res.end(JSON.stringify({ status: SECURITY.ACTIVE ? 'AKTİF' : 'DURDURULDU', mesaj: SECURITY.ACTIVE ? 'Sistem açık' : 'Sistem kapatıldı — tüm API erişimi engellendi' }));
    });
    return;
  }

  // ── ADMIN: Durum ───────────────────────────────────
  if (pathname === '/api/admin/status') {
    const auth = authenticate(req);
    if (!auth.ok || auth.role !== 'admin') {
      res.writeHead(403, HEADERS);
      return res.end(JSON.stringify({ error: 'Yetki yok' }));
    }
    res.writeHead(200, HEADERS);
    return res.end(JSON.stringify({
      active: SECURITY.ACTIVE,
      uptime: process.uptime(),
      memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB',
      endpoints: Object.keys(ROUTES).length,
      version: 'ERPBI v10.0'
    }));
  }

  // ── Swagger / API Dökümantasyonu ───────────────────
  if (pathname === '/api/docs') {
    const auth = authenticate(req);
    if (!auth.ok) {
      res.writeHead(401, HEADERS);
      return res.end(JSON.stringify({ error: 'API Key veya Token gerekli' }));
    }
    const docs = Object.keys(ROUTES).map(r => ({
      endpoint: r,
      method: 'GET',
      params: 'company, yil, ay, aylar, limit, hesap, dim1, dim2, musteri, satici, depo, renk, boyut, config'
    }));
    res.writeHead(200, HEADERS);
    return res.end(JSON.stringify({ version: 'ERPBI v10.0', endpoints: docs }));
  }

  // ── ADMIN: Kullanıcı Yönetimi ─────────────────────
  if (pathname === '/api/admin/users' && req.method === 'GET') {
    const auth = authenticate(req);
    if (!auth.ok || auth.role !== 'admin') {
      res.writeHead(403, HEADERS);
      return res.end(JSON.stringify({ error: 'Yetki yok' }));
    }
    const users = Object.entries(SECURITY.USERS).map(([k,v]) => ({ name: k, role: v.role }));
    res.writeHead(200, HEADERS);
    return res.end(JSON.stringify({ users }));
  }

  if (pathname === '/api/admin/users' && req.method === 'POST') {
    const auth = authenticate(req);
    if (!auth.ok || auth.role !== 'admin') {
      res.writeHead(403, HEADERS);
      return res.end(JSON.stringify({ error: 'Yetki yok' }));
    }
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        if (data.action === 'add') {
          if (!data.user || !data.pass) {
            res.writeHead(400, HEADERS);
            return res.end(JSON.stringify({ error: 'user ve pass gerekli' }));
          }
          SECURITY.USERS[data.user] = { pass: data.pass, role: data.role || 'reader' };
          res.writeHead(200, HEADERS);
          return res.end(JSON.stringify({ ok: true, mesaj: data.user + ' eklendi' }));
        }
        if (data.action === 'delete') {
          if (data.user === 'ustad') {
            res.writeHead(400, HEADERS);
            return res.end(JSON.stringify({ error: 'ustad silinemez' }));
          }
          delete SECURITY.USERS[data.user];
          res.writeHead(200, HEADERS);
          return res.end(JSON.stringify({ ok: true, mesaj: data.user + ' silindi' }));
        }
        if (data.action === 'changepass') {
          if (!SECURITY.USERS[data.user]) {
            res.writeHead(404, HEADERS);
            return res.end(JSON.stringify({ error: 'Kullanici bulunamadi' }));
          }
          SECURITY.USERS[data.user].pass = data.pass;
          res.writeHead(200, HEADERS);
          return res.end(JSON.stringify({ ok: true, mesaj: 'Sifre degistirildi' }));
        }
        res.writeHead(400, HEADERS);
        res.end(JSON.stringify({ error: 'Gecersiz action: add/delete/changepass' }));
      } catch(e) {
        res.writeHead(400, HEADERS);
        res.end(JSON.stringify({ error: 'Gecersiz istek' }));
      }
    });
    return;
  }

  // ── ADMIN: API Key Listesi ─────────────────────────
  if (pathname === '/api/admin/keys') {
    const auth = authenticate(req);
    if (!auth.ok || auth.role !== 'admin') {
      res.writeHead(403, HEADERS);
      return res.end(JSON.stringify({ error: 'Yetki yok' }));
    }
    const keys = Object.entries(SECURITY.API_KEYS).map(([k,v]) => ({ key: k, role: v.role, label: v.label }));
    res.writeHead(200, HEADERS);
    return res.end(JSON.stringify({ keys }));
  }

  // ── ADMIN: Config GET — ayarları oku ─────────────
  if (pathname === '/api/admin/config' && req.method === 'GET') {
    const auth = authenticate(req);
    if (!auth.ok || auth.role !== 'admin') {
      res.writeHead(403, HEADERS);
      return res.end(JSON.stringify({ error: 'Yetki yok' }));
    }
    CONFIG = loadConfig();
    res.writeHead(200, HEADERS);
    return res.end(JSON.stringify({ config: CONFIG }));
  }

  // ── ADMIN: Config POST — ayarları kaydet ────────
  if (pathname === '/api/admin/config' && req.method === 'POST') {
    const auth = authenticate(req);
    if (!auth.ok || auth.role !== 'admin') {
      res.writeHead(403, HEADERS);
      return res.end(JSON.stringify({ error: 'Yetki yok' }));
    }
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        if (data.sql) CONFIG.sql = { ...CONFIG.sql, ...data.sql };
        if (data.server) CONFIG.server = { ...CONFIG.server, ...data.server };
        if (data.tunnel) CONFIG.tunnel = { ...CONFIG.tunnel, ...data.tunnel };
        saveConfig(CONFIG);
        CONN = buildConnStr();
        res.writeHead(200, HEADERS);
        res.end(JSON.stringify({ ok: true, mesaj: 'Ayarlar kaydedildi. SQL bağlantı dizesi güncellendi.', config: CONFIG }));
      } catch(e) {
        res.writeHead(400, HEADERS);
        res.end(JSON.stringify({ error: 'Geçersiz JSON: ' + e.message }));
      }
    });
    return;
  }

  // ── Statik dosyalar — auth gerekmez ────────────
  const isStatic = ['/', '/index.html', '/manifest.json', '/sw.js'].includes(pathname);

  const filters = parseFilters(queryObj);
  const handler = ROUTES[pathname];

  // Manifest
  if (pathname === '/manifest.json') {
    res.writeHead(200, {'Content-Type':'application/manifest+json','Access-Control-Allow-Origin':'*'});
    res.end('{\n  "name": "ERDEM HOLDİNG BI",\n  "short_name": "ERDEM BI",\n  "description": "Erdem Holding CEO Intelligence Dashboard",\n  "start_url": "/",\n  "display": "standalone",\n  "background_color": "#050d1a",\n  "theme_color": "#1B6BF5",\n  "orientation": "landscape",\n  "icons": [\n    {\n      "src": "data:image/png;base64,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8lsqWu7Qb/kZcNO/m7s1LVgsFjU4/ZqfH18TymGnnVmeKqqHrsoyoix3LZauDqoqpg6rtQkZqQICaPBWNIzyUtUQnKwpYyO5WIyKkomAWr5KyXsVotKkTImi0VRfZaqFZNT5RVIVEAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBEVQgKKoQL6wgKBVAX0ArjWLFzKR8Bue5XGM8lcYzPcr8cRPctWzdRLLIye5ZMUKvRwknosyGn8lG5E0YFmCA5UjTQeSuU9MfBSVNT9FBKZZp0z4pafpspOniOWsYCXOOAMLd+GfCvVWtpGyW6j9Vt2cPr6gFsXny97z16fEhd7o9P8K+B1tju1/rY6q78vNFLO0PqJD/MxD6oz9ruzu5cyvjYxlkis0uSLDlGmrsemBL9FejrcaCn9lkklJSjH3RKx2P9ReOeDNwZZNU1Oon0/rP0RQTVTYi7HMfZjxnu2kXdOKHFOTi7wv11b6e0toaa0w0lfRxl3PNIxtQGyueRsMNc04A2wdyuAcLmw1V/q7TO57G3K21NMCxoc7m5OdoAyMkuYABnvCzgMNOhhZ0qqs76+KXyKdGrmxEJw8O/h5m9W7Rs2qbZeLjoqOOspZadjIRVFsdRHNIYjKC8Ow/2RJzc2Nz7IwQuW1FludsvMFDdrfVUcpma0sniLCdwNsjcL0p6MbrXBouroaKtpKmdtY6WR8TsOc1zWhpc0+03GCNxjY4J6rcNb6Oh1M+mqG3W42yqpyOV9NLhsjc55ZGHZw6/NaLaLoVpU5LTnxPQPYscXhoVqb63Lhv4f7PG2o3mXUNylJJL6uVxPveV7X0TdLZdtJ26vtdT21GadrWvdgOHKMEOA2DgQcryLrO5V1u1bdqAG0VIp6yWPtRbad/NhxHUx5K+9PanvTKG7MiqIKaKOjc8impYofaLmMByxoOfaCtYzCvFU42drfM5+zNoRwFed03f5X7T2iCCMggg9CtG4t3mp0npO5XylpW1LiYzEHODRBMTydpkODjk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yQTio56l8slXWDlgkd7Mrz7OcAHDRkEhfPpeHHFMH/2dD/aeuHiItbRV011eLu977WvBHVwDWVnEK1/XdQtW/rupOtfuVC1bvNdSCJKrMGpcsGVyyZ3LClO6tRRRmy24q2V9HqvkqQhZRERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAX0CvlVCAvxdVmQHdYUXVZkB3WkiWJKUh3U1RO3Cg6XqFM0R6KtULtJnpz0Kd7zqL/Jof7TlwbjR/G7q7/PNV/tXLvHoTnN51H/AJLD/acuD8aP43dXf55qv9q5U9lf1Ct3L5FbaW5GooiL0xyToXDykkruFXEulifGx76GgwXnDdq2M7n4Lng0nUj69xt4/wDeH/gujcNf4ruJX+Q0P++RrRFTo0ozq1W+a/xiWoytCPrizsmteGtDqaXSVVcNVUVvgo9JWyKePGZCBEcOBJAwd/l0Wo3CDT1hlFutV2p6ynjH12MLd+/Oep81l8a3ObUaQAcQDpG25APX8mVz5RbPw0owU3PR8LL/AGW6uJp5FCNNJ8Xd/wCjfNMmjvepLXZY6wRvuFZFSteGF3KZHhgOO/GfFYkdXTSVDqdkwdI0kEYI6deq+uBtOarjBpSMNzi6QyY/QdzfsUDqeJ9v1ddYBlj6evmZjwLZCP2K2pfxnT7E/NkPSvLc2NZlnuldaK1tZb6h0MrdsgZBHgQdiFG01TFNStqOcNaRvk9D3hRd5usRhdT0z+ZztnPHQDyWzgprK1dEyq9G1OLszolRrakvzX0mpbVQ3CmkZ2T3U7jHMG8wdgODumWg426BQd64d2y7Wua5aEmraiSnOZ6CqLe1LfGPHXHgevcc7LUdP6duN5imqYAyCip8dvVzEiOMnoMgElx22AJ3UvZm3KyXdtTbrnJ2bOj92O+AyRj47jqqfssabaw8srXDh4r6alp4qWISeKhmT47peD4+aPSHot2p1HpqyxSxOjlayaeVrm4IcXuxkHwBHyXfF460vxou2lqrtqttNWzO2JeOQlp6ghox3DfAO3VeiOHfFbSmsbe2SOtht1aAO0pamZrT72OOA8de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h8me9W3v81aLsqRIhci456tlx8V8kqhW1jS5XKpnzVCqLJgrlMqiICuUyqIgK5VERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAVQqIgPoL6BXwECC5ea7zV1knmsYHC+gVq0bJmayXzWRFMo1r8d6usk81q4kikTEU6zYajzUDHKQsqKY+KjlAmjUNjp6nzWx6W1HdrBco7jZbjUUNUzpJC7GR4EdCPI7LRoJ91I01R5qvUppqzLVOqetNAcfbPfKL6C4i2+maydvZvqhD2lPKPCSMg494yPJoU9e+Cun9RcSLTxIs16M8ZrIqypgdIJoakMwQY3g7fVbscg79F5BpqjOy3bh9xA1NoqsE1kuLm07nAy0kvtwye9vcfMYPmuRPBTotyw0sraatw1Np0YVUZtPSaj0yOKWrdTW2qt95jtz4WNmbgiaunEZkY7o7DTJhwOOq8+L336a/O/gJXOj3b65TF36PP8A8SF4EXR2bini4SrNWd7e5I5dSn0byo9JaeHZ6fsvUdnoKtk6eLol0vhe3l4baaH/ALKpj08Y2lc0oh2enKU4xycNpnf1gw/sXUeHbeTh/pxv3bVSj/4TVw8X9jx+p9B2b/M/7fp9CSvNvobpbJqG40sVVSyj24pG5a7ByMjyIHyWWAAA1oAA6DCpJ/BO9xVVz7u1jsqKvc0bi9sdHu+7qmi7vHnH7VybV7P/AAG4nMx9TU4f85Aus8YtqPTD/uamoHf65XLNXs/8FOLjMfUvVM/5zNXXwP2I96/yR5vaq/iT7n/hL6HEqCrqKCup62kldFUU8rZYntO7XtOQR7iAu88RND37WvFyom0jZpaqO901Ldw5g5YohURNkc57z7IHOX9Tv3brz+v0Z0ZdqjTfoy2W+QxxOqaTTFPPG2QHlc4U7eTmxuR9XvXUx+Mng5RqU1du699voeKp0VW6rNF0FwD0XoS3DUfEa5UdwnhAcWTO5KOJ3hg7ynwyMH7qweJXpDFkLrVoKlbTQMbyCvmiAIA2HZRnYDpgu/qhcW1rrDUGrbga/UFylq3jPZxk4jiHgxg2Hd+1apVVHmqawk68+kxUsz5cF4HTp0YUVojNvd4rbnXTV1xrJquplOZJpnl73HzJUJUVPmrVTUeajp5/NdSFNI0nUL81R5rDlnWPLNv1WM+UqdQK0qhekmWO+Uq2+TzVlzz4qRRIHIuPk81bc8lfBcvknK3saXKlyoVQqiyalSVREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAVCBURAfYK+g7CtgqoQzcvteR3q9HJhYfMrjHrVo2TJOGXBWfTzkHqoSN6zIJcd6jlEmhM2Gmn6bqWpJwRutYppum6laSboq04l2nUPbmu6Q8RfRbq2UoM1RVWSOoY1u5dPDyyFg8y+Mt+K/PRe4vQ31nHWWWs0XVzfl6RxqqME/WicfbaP0XHm/pnwXnL0nuHE3DziRVNpoC2yXRzqq3Pa32WtJy+L3sJx+iWnvXK2VPoK9TDS53XruKuLhrmRvc9RRQ0NJbKm4UNFNW8PI6SmNXUNia+R4LQ3LiB3LYtN63rbBp630uotK3CnoaWmjg+kqCVldT4Y0N53GM5YNvArz/TcRLwaemprvbbHfYaWFsEAuNuje6ONuwaHtDXYHvUvaNcaPiqO2OlrnYKk/WqrDdXxn4Rvy38VJUwMmrSjfu/2vgzu0drQUs0JZe//T+MT1Tabrbb1a23C010NZSyNPLLE7I9x8CO8HdYWq9V2LTEEcl3rmxSS7Q07Gl80x8GMbuf1brz3adV0FBdHXXS2tIKSqmBE9NeLa6BtQMbdo6DMZcOodhrvElYzNSWajrJ7ld9dV9bc6j+6JrJQ8szvIVE+Cxo6crGtbt0VJbM62t7dzv8PM6ktuLJpbNzurfHy4HTNaX686kitTX6ZfYrXBc6esdW3iuhpn8sb8n8kTzdM960++VNJcdPcYJqGphqaZ9VRSxywvDmPHaZyCNj0WmVmstHRTOmodDG41R61d6uMlQ5/vYMN/FRN217eq211VppaW0Wm3VYaKimt1BHC2XlORzHBccHzXRo4OUbJK274p83y7DjYjaVOTblK7ae7ti4rhHTXtNfs1uqrvd6O1UMZkqq2dlPAwfae9wa0fMhfoD6QM1NpTgI+ywPwHR01sp+7Ibyk/6kblwL0IeG8t61c/Xlypz9G2dxZR87dpqojqPEMac/pFvgVsPpg60juurKbTFFKH09oaXVBadjUPAyP6LcD3lwVXHS9pxsKMd0NX69bzlYSFlmZw2rn64UVUz+a+qufqouplyuxCBNUqFJ5iT1WDNLkpNLlYkjzvurEYlOcz6fJ5qy55K+HOXwSpEiFs+i7K+cqhVCtjW4KFURDAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAVC+gcL4VQgLzHYWRE/Cw2lXmO81q0bpknBIpGmm81CRP36rNglx3qGUSxCRu+itSXHTOoaK+2qfsqukkD2HucOhaR3tIyD5Er2ZPFoz0g+FLqeccjnYLgCDPbqkDYjx7/JzSfh4Mpp/Nblw71vfdE32O72KrMMo9mWNwzHMzvY9vePxHUEFcnH4J1rTpu01uZaTUlZkFxY4aan4bX51uv1I40z3H1SujaTBUt8Wnud4tO492CtLX6C6L4scPOKNkNg1NTUVLVVDQya3XENdDKfGN7tj5dHZ6eK0zXvokaYuU0lXpC+VVje48wpahnrMHuaSQ9o95ctKG2FB9Hio5Zc+DKk8M19k8WovQFx9EviXTyltLX6drGdzmVUjD8Q6MfrV+z+iPxCqZR9I3fT9BDn2iJpJX/ABgB/rK9+88Ja/SIh6GfI88LqvAbgpqDibc46l8ctu05E/983Bzcc+OrIgfrO8+je/uB9IaA9FvQOmC25aorZtRTwjncKkCCkbjfJjBJOPznFvkszihx90xpSgdZNER0tyrYmdlG+FoFHTAbDGNn42wG+z59y59ba0qz6PCRu+fBeu0np4Z3vImeKWstPcF+HtLp3TcEENf6v2Nso279kN8zSeO+Tvu52fziPFF0rpqqpl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GldbJab1mu0vBEw/bp6l0Ofc0k5+S2zS5ef1sQunJO1jTUW0G36XqQTFUXajPeXxMmYPkQVadpyml3odQ26QeE/NC7/WGPxWc64o1sa4inZdJ31rS+KjFSz71PK2Qf6pyouqoaykdiqpKiA/zkZb+sLZSi9zFjGREWTAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAF9NBc4BoJJ6Ad623S+lIqqi+lLtMYaMNL2sacFzR3k9wWZDfaOJz4bDT0Vsp2bOqpWh0rvcDue/qoXVV7RVzZQbNZpNO3yqAdDa6otO4c5nIPm7AWWdJXWNvNVSUNL/jqpg/UStjjmoqtxNXcqmscdz2z3MZ/VGGr7iqrDAcRvoYyPANBUTrz4LyLMcKmruSNYbponY36yDy9aJ/U1Haax/wDf9jP/AOpI/W1bfFdre94ZFVxOd3NYcn5BZTJ2yNyCcHxGP1rV15reSLBxe6Xr3mjt0pcZRmlqLdVeUVU0/rwvk6S1DnH0c739qzHzzhbrLBSTDEtNBJ+kwFYstspeTlgfNTjwjkPL8WnI/BFiZGJYJrczWjpKsgjEtwrqCjYfvylx+AaCr79P2eli7aoudXWRj6xo6cco97icfgr9dDLbD2smTA44dPS/k3t8OZn1SPl71RkLu2jkyIRI3mhr6YcjCPzxsB54wRv1Uyk5a3Kk4yg7NGKyXTcBxDZqiqPc6pqiPmGAfrUhFWVkTo/VLTaqJjuk8dMJMDzceZY76JtRUOoq801NXZ5Y5GHaQnoHBuwzt7W3XfKwmPbQvki9bqGuBLXsZGMZ6Ebn9i3yxlu+bMQaT65LzV13kkLbheattOdmvgdiM+RLdh8lHzwUna8tTJLG927JTKJWO9+ACrZfLOzLaOqmZ/OyOLP9UNwvkGSPp6hA33NeR/acsxi12EjqQ3KPvMumnpe1dGII3SNPsiCEPY73kguX1IKhrswU8kTS7L4piIonf0S73d6xxdIaaEiqE9xyejKl0bWj3cu/evmSaklp/XKWGUszh0bpiezPgdskHffKxls9TbpZyjpwM58r3NLHuoo2d8YD3ge4D2VagxGOzZWVsjc7MZiPHu+so71+Rv8ABRQx/wBEv/tEr5dcK1wx61K0fda7lHyGykVMjdaTd2yXfTOecyUbneD6qV2fmSB+Cp2b2dKympz/ADTBn+sxv7VB9rJnd78/pL6bMcjmdLjvw5bZDTMmSk0VPKeaetq6gjxH7ST+pfHZ0jf4Om5v8c8n+zyrFYJi72WVGO7LcrPqaSopzG17HO52NePZ8R0S6WjZlJMtc8o2i9Xj8OWFuR8Tk/itw4f358bxbK+Rr3OP5CV31s/dJ/V8vBaaTyAh7HAnp3IXcj/ZdnHQjKWQsds7f/nKxZ5Yy7AY3bqcLXNLXz6Ro+ymcPWYhh+T9Ydzv+KkO178n5qni5NRyriZgtSRi7Jz8vYw+RCpJ2THnkYz5LCidzbnp71SR/KfJVckui3G19SRgmYDgsbk9DhZHbqEE2/X8VH6qvn0fR9lA4esyjDfzR3u/wCCtYSTlGz4Gs1qRfETUvNL9F0Dg1zD+Xmb1z90H9fy8Vpnr0p/hI4JB380Tcn4gZ/FXXkuJPOcnqrZZzfbPyH/AAV1JGrRTt6V/wBejDf8VKR/a5l9wzU8Z5oKurp3HuDc4+II/UrRgaT9Y/JfPq4+/wDgs2RizMwyzP2FXR1J/nWDPze0frVBFId/o0OHe+me4/iC4fgsQUziQGuyT0GFQ072nZwBC1yoWZlRVEUR5WS1UGDnlc1su/xwvqeX1qdkstVTTOb9l7XMLvI7Y/FWRLWgAesuc0fZe4uHyOyrzPP8JBSyf0eT+zhYy63Ns07WvoZz6ieRzS2mlLWdIqWoaW/JoyviWop6iXtLi0skb9WEsLR8XYJKxXeo00QqammcRnDYmy4Eh+WQBtvlXGXGlniAp2T0DQejqh0jXfABRZVeyRM61Rfa1ufZbQ+stfBI4yP+rHC7kDP6RUgyqutEzH01VD8xx5mAe95AKjiwzM5oxRTDzDWZ/suXy6nZyflaKohH5jzy/iD+tZcb72Y6SLveJmmumqQXz2611kf2ppaYRH+sCPwWNLHYpAO1s8kGTjmpK0PyfIOyrMkHrTmRirnc7YMa9mR8wf2K62lr6eR1HRmldMCWudE72/MZdjz6LGRL1Y1vFvj69cyzLabG8+xc6ykP3amlz+LT+xWXaclfvSXO21Pg0T8jj8HAL7gpq54kMs0kNO1vNLK5xLMfDqTtssdtQx0ohttIJHno+YBzne5v1R+PvR6cSPfuPsaWvxOBb3e/tGY+ecL6dpe4RD981FBTf42paP1ZVuanvk7S2SOqcwfYyQ34DosX6MuH/wCCn/qFYzS5o2yPkZo0+O++WUf/AKk//Sh094XyzO91SR+tqxG2y4ux+85vi3CPtVxbjNHL07hn9SXf4hklyMxulrnIOamfR1P+KqWH9ZCxaqw3mmHNNbajlHVzWcw+YyFiz088BxPDJGe7maQsmjutzpCDTVs7A3oOclvyOyz1+DMWtvI9wLSQ4EEdRhfK2ul1JT1pEF/oIKlhGO3azD2+e37ML51JpqOmpPpG2SmalxzFpOS1p7we8IqlnaSsYsasiIpDAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAdH0tWMvWmn2yVrmGKEQucO8Y2I88DooOgLLfWyWKuhjqBz+y4NyMkd+URU7WlJFik7SRIOsltdjMUhA6NMjsD8Vg3G12ijHaSx1Jad8Mfn9aItIzlzLs6cFG9iMfU2QD8nbZX+b5i39RX1SXeCmJMdva7fLS+UuI/BEVpQTWpRc2np8DI/dNOMllHTtz71VuqasH2qeE+4kIidFDkY6epzLc15rbri3iOCMTODc7+P/AD3LIMAqZ6azROLY6QP5pHdXH6ziB8NkRElF6Gk5OWrKwytuN7fWOBZDTtEhb9osYBge84H4rCqblUzVMswf2Re8uPZgNO5z1HX3oilglfwNGWm1dS0l3bPPeeY5/Wvo11Qe+I++Jv8AwRFJlXIZmtzLkNTI92HNicO8dmBkfBSFNZGt5pqWrfEyVv1THn2T3dURVq8nDcWsPFTvmKVVFNQwtlL4KlnMGkSMLSPDGDv8VaNRDn+4Yh/TcURbUevG7MVepNpB1RFj2aGmJ/OB/wCKs+tioY4CipGbdQwgj8URSKC3kOd7jF9XP3h8lSqdI4sMj+YtYGjyAGwRFJxNGrFvtJB9t3zUvbLPXV0QljqIms/OJz+pEUdRtK6ESXstoqaauZPFX+3Gd29ns4dCM5W1vf39x6hEVOUnOLuTSilax8dq9jsAqvaPe7BKIq635eAKtk3zvt0WrXi21FRVSVMtUHOedhy9B3BEU+dwSym1KKk3ciKmhlp2c7nsLfLqsTJRFdg7q7NZpJ2QyVTKItjQZVeYYI35vFEQDKzbVZ6q5Qvl9bZCxruUAMJJ/FEUVeTjG6Ber9NCJnrVZXOlbGAOVse+B3ddlEubGTtG0DuCItKE3K9zLWh8lhb/AAbi0+HcVWnqHh2xLXDvaURWDQzIK6eKeORzu0LHBw5xzdPM9FkSyGhuzKpoD4ZgX8vR3K4bj37oiiklczwLEjOynntExBZVBvI9o3BzlpI/WoUF9ur3BzI5JIX43Jxkd/ciLG/3GL2ZMHU5wP3nv/jP+5U/dM/P9xjGP5T/ALkRadFDkTPEVOZT9079/wB6D/Sf9yo7U03dSs/rlEWeihyDr1OZan1DNNGWGlgIPc8FwUZLVSulMjMQc32YvZb8giLMYpbiOVSUnqy5QU8tyrIqYPAe8n23klbdqKrZadPNt0TXPMkRiDj0AxuffuiKOprOKC3M0FERWDQIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgP/9k=",\n      "sizes": "512x512",\n      "type": "image/png",\n      "purpose": "any maskable"\n    },\n    {\n      "src": "data:image/png;base64,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8lsqWu7Qb/kZcNO/m7s1LVgsFjU4/ZqfH18TymGnnVmeKqqHrsoyoix3LZauDqoqpg6rtQkZqQICaPBWNIzyUtUQnKwpYyO5WIyKkomAWr5KyXsVotKkTImi0VRfZaqFZNT5RVIVEAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBEVQgKKoQL6wgKBVAX0ArjWLFzKR8Bue5XGM8lcYzPcr8cRPctWzdRLLIye5ZMUKvRwknosyGn8lG5E0YFmCA5UjTQeSuU9MfBSVNT9FBKZZp0z4pafpspOniOWsYCXOOAMLd+GfCvVWtpGyW6j9Vt2cPr6gFsXny97z16fEhd7o9P8K+B1tju1/rY6q78vNFLO0PqJD/MxD6oz9ruzu5cyvjYxlkis0uSLDlGmrsemBL9FejrcaCn9lkklJSjH3RKx2P9ReOeDNwZZNU1Oon0/rP0RQTVTYi7HMfZjxnu2kXdOKHFOTi7wv11b6e0toaa0w0lfRxl3PNIxtQGyueRsMNc04A2wdyuAcLmw1V/q7TO57G3K21NMCxoc7m5OdoAyMkuYABnvCzgMNOhhZ0qqs76+KXyKdGrmxEJw8O/h5m9W7Rs2qbZeLjoqOOspZadjIRVFsdRHNIYjKC8Ow/2RJzc2Nz7IwQuW1FludsvMFDdrfVUcpma0sniLCdwNsjcL0p6MbrXBouroaKtpKmdtY6WR8TsOc1zWhpc0+03GCNxjY4J6rcNb6Oh1M+mqG3W42yqpyOV9NLhsjc55ZGHZw6/NaLaLoVpU5LTnxPQPYscXhoVqb63Lhv4f7PG2o3mXUNylJJL6uVxPveV7X0TdLZdtJ26vtdT21GadrWvdgOHKMEOA2DgQcryLrO5V1u1bdqAG0VIp6yWPtRbad/NhxHUx5K+9PanvTKG7MiqIKaKOjc8impYofaLmMByxoOfaCtYzCvFU42drfM5+zNoRwFed03f5X7T2iCCMggg9CtG4t3mp0npO5XylpW1LiYzEHODRBMTydpkODjkFvst+6c9Sob0Z7/UXrQEkFZJPNU0NW+J800rpHSB3tg5PhkjHkFE+kTBX3q7WPTvr7aW2SyRmRsbeeWaeR5ZG3kHhhxBcWj63UtwuJRw+TFdFPcnqeqxOM6TAdPTWrWnY3p5HCeJkEVPxAvjIWhsTq2SVjfAPPOB8Mr3VWOkv3on000oMssul6eZ2Bkl7IWPJ+bV4Q4g1sNx1xeqynIMElbL2Rz1YHENPyAXsPQ/FOs0lrXS/CWptDKunjtltoTLG7llp6h0EZeXA7OaMgkbEb9ei6W0aFSpTp5Fdx63grXPCOpGFeb4N/M80Txh4JUXU0/XZextTcNOHXFKjqLzo+5UdHcGvLZZaPBjMneJYti0nxGDvn2l524icPNTaLq+xvlvc2FzsRVcXtwS+53cfI4PktsPjoVXl3S5PeXbxqLQ5fUweSj54d1s1TTeSjqin67LpxmVp0zX5YsLHfGfBTM1PjuWJLDv0UykVpQItzCO5Wy3Cz5IsKw+PyUiZE4mKQvkq+5mO5fBC2uaNFsqi+yML5KyYKIqlUQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBEVcICiKuFUICgVQMqoC+2sKGUj5DV9taSrjI/JXo4s42WrZsolpkfkr7Iir0UWVlxQKNyJYwMaKHKy4oMrJhp89yzoKbyUUpk8KZiwUx8FnQU3TZSdntFXca2KioKSaqqZXcscULC9zz4ADcr0Nwx9HSV0cd015UijgaOf1CF458dfyjxs0eIGT5hUcTjKdBXmyxGCW84jonRt+1XcRQWG2TVku3O5owyMeL3HZo95Xo/RvBXR2hrX+6LiHc6KqdAA5zZn8lJEfDfeQ+AOx6cpWPrrjroXh5bXab4d22juNTDloNOOWjid4ueN5XdM4O/e7K8za11lqzX139cv1wqbhKMmKBg/JwjvDIxs339dtyVDSwmMx2sv4cPN/T1vK1XGxh1Yas7rxS9JkMifZ+G9G2CFg7MXKoiAwBsOyiIwB0wXD+ivN94udxvFxmuN1rqiurJjzSTTyF73HzJW48MtKWm80NbdrlNNUNoSS6ggGHvAbkZOe/cADHTqpyKn07r3TNbBZbNBa7nQe1TsYGhz292SAM53G/Q43XSoey4BuFKG62aXfz4/Imp7HxOLpKpKaTkm4R4ytvtbReOprfBi60Nt1vHRXiQMs96ppbTcXZ+rDO3k5s93K7kd/RWiXq33jQuuqi31ANPdLNXY5sbc8bstcPFpwCPEELIe0scWOaWuBwQRuCui6gt7uLOjortQDtdcWCkEVdTD+EutFGMMmYOrpYxhrh1c0A9dlYxkOjn0v3Xo/k/k/A5FCb+zxW4jtKR1Fp4iWfW2n4Kj9ztwqR6x2ALhSc5xNDIB0DCcjPVvIV3viprSDQ2mTdpKZtVM+UQwU5k5OdxBOc4OwAyV5J0lqSexSS080JqrbUEesU3aFhyOkkbhuyRuThw8SDkbLqd1uL9e6ft9Fbamkvc9DGWxetxtNUR92Zn184DR2kJcCRl2M+zxMXhM1WEp/ZXw7T1mzdoZMPUhS0m9UuT42XLj2ce3nOrq60Tahqqqpsrues5awmCrLATM0S9HB2PrqlsrrVTWG7VUNjY9rxDSltTUyPDi5/afYLD/AIEqT1PST0lsgluujY6Wpo/3tOwunbhmcxvBLyHNOXNyMj2W77tCzKKxV9bb6O20GjYXNc71mrklFS5sTiMMZ7DwXPDMu5QCfbIxkFXs8FBfXl4nK6Ko6st1+7n4erHQPR+1zZrZoa9Pu76G109FVtkayJvLzdozZrckl7j2bvE7eC1G9anvLmXLWN5glojU1MhsdNMHCR0joxGJN/sQxlxBAx2knvxYuNXSad5GXCpht8NPvDabYWNrJ5O980zc9gDt7PMXBoAxnLjo15ud51jqGImF9RVTObT0lJTsJDBnDY42jJ6n3kkk5JUFLDRlUlUto/XnxZbxGOnChCi3rH4833cFpzehNcEtNQ6n4h0MFeQyz0AdcbrK4ezHSQ+3Jn34DR5vC6doS9zXLXusuLlc0sZaqeorIOboKmfMVNF8OY/1FFXeiGgNJHhvaSKzVd6kiOoJKY8/ZYP5KgjI6kOIL8dXYG6+uJPJpfTlt4XW1wnro5hW358J5u0rXDlZACPrCJpx5uJ71bjHpn/fov7fvPx3LwZ5+bt4fHgXODdwrdJaU1jrykndT1VPSxW23vwDmpnkBJAOxLWRudv4rrvDb0j7JfqMWDiXbqeHtm9m+sbD2lLMP5yM5Le7cZb+iFxviyY9M6esfDWne0z24GvvRYch1fM0ewcbHs4+VmfEuXNVJPZ9DHxdSqtW9HxS3L37/E0VadFpR4HrviBwBs99ovp3h1cKdrJ29pHSmbtKeUeMUgJ5c+ByPMBecdUabu1guUluvVuqKGqZ1jlbjI8QehHmNld4bcS9XaArRLYbk4UrnZlop8vp5fe3Ox6e00g+a9N6U4q8M+L9sj0/rCgp7dcn+yyCsdhpedswzbEOO2x5T3e0uVWoYzAav+JDmt67zp0cbCppLRnj6em67LBmp/JeluKXo73i0iW4aRkku9CMk0rgPWYx5Y2k+GD5FcFrqCWCZ8M0T4pWOLXse3BaR1BB6Kxh8XTrxvB3LEqae41eWBYksK2Gem67LCmp/JXYzK8qZBvi8lZfH5KWlgx3LFkh8lKpEEoEc5hXwQsx8Z8FZezyW6ZE4mOVQq6W47l8Fq2NbHwi+iqYQwURVwqIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCKoVQgKYVcKvKvoNyhmx8AFVwroYSvoMWLmbFgNKqGrIEfkvrsli5nKYwYfBfQYVkiM+C+2xHwWHIzlMdrFdZETjZZDIT4K/HBlauRuoGPHFlZMUKyYoOmyzYKbyUbmTRpmLDT+SzYKbyWXBS9Nl0Dhpwt1TredptVCYqIOxJXVALIWeODjLj5Nz54VarXjTWaTsizGmaHBTEkADPwXZuFvAbUuqBFXXdrrHanYcHzM/Lyj8yM7jPi7HXIyuuWrR3C7gra473qivgqroBmKapaHSOcO6CEZ8t9yO8gLj/Fj0j9R6j7a26TbJYLY7LTMHfvuUebhtH7m7/nLn06mJxztho2j+J7vA0q4mnRXadgu+puE/Am3SUFuhZWXssw6CFwkq5D/OydI29NtvENK848UuMesuIUr6SpqTQWpzsMt1GSGO8Oc9ZD067eAC1zS2kL3qeR1TG3sqUuLpayoJDM95z1cev7Stu4R0NBTXq+0kMlFWXWmafUZz7UbgMjmbjz5c47ir9HB4XAqVR/xKi3t8Pp8RhsDisfUpxn1ITbSb42V9OfZwuaHPYLlbvVKm9W+so6GaRodIY8ENJ3xno7GcA+C7JBS1Gna+0UWkLBTz26rAfVVpdl7mZGcu7tiHDffoAtf0dfanVTrto/Vjs1M/P2LiwNMb29WgDvaQHD3FWtOXSNumL3onUFzFuqKFr2Q1BkLctB+qCNyAcbd7ThbYqdWt1ZrVb0rtNPdLtszvbLpYXCfxKMnae6TspKUdXBt3SzLiX78yq0RxBGo4oAyyXGQRziM5AyAXEjuOcuHuKzJ6DTei9T1GqZLxyR1LC6noIACZOcZPfu3O46Abbrm7NW3AaNfpiSOCamMmWySAl7G5zyt+Od/MrN0loK9agoH3usnp7Lp+H2Zrvcn9lTtx9lmd5HbYDWg74GyllhMkL1p5V9l/mXDx8zn1Nu0YSvh6ea7zpP7k39pK1rrityNevlYLpe6yvigEQqp3ytibvjmOcLqPDfhbqWge3V14ra7TrLdD9IRU9HH2l1njaQC6KnG4bvguftvuCFF2jiboXhze6R2idNN1JNBKPWrzdwY3yt7xTRg/kPJ7uZ2+4WHqWx3uruMnFXhlqa7X2KOT1ipe+Yuutrd3tnaDl7MZHOMtIBzstcRi6ko9HBZIvRN8ezs8fdc8+qeaTqTd23cyNVVnDDixe6yqoXDQOoZHkxvr3tdQXE/elcxoFPKdySByfE5XP9Y8P9Z6NeJr1Y6unpzh0VdCO1ppB1DmTMy052PXK2uXVegNf769tkunL+/61/stOHRTu+9UUuQM9SXRkEk9FO6U0vxVsDHTcJ9c0WoqA5cYbRc2k4/nKSYg8x8OVyqxnKgst7LlLd4S+vuRI0pa/D6HMaHXms6KIQ02qLs2MDAY6pc8AeQcThWbtrLVl1jMVw1HdKiJ31o3VT+Q+9oOF1Wvv3FyGQjUPB603KfvnrtEtLnf0mRgfJXrReuOFTIBpXhhR2OQ9J7dpCKDH/vHxkA+eVt0kV1sse+6+hK61VrK5u3j9TnmkuFmsdRUhuX0e20WZgzLdrs/1Skjb487/re5ocV0TQGpeGmgL62yadpb7qa71zHUs2pKBjY56Z7/AGcUMD2uJ6kcxLXHJxso7U+jdUV9WK/jNxMobQY9/Vamv+kK1o8I6eEuDfiWjdRX7vrLpiN1o4RWOrpa6oHYvv8AXgS3Obm2LYWt9mAHJHs5ccjfK1m5YhWvfu0j4vj4eKI1aJ1Sr0PLwrtV31RYpHas1FE8xR1EcbSbG17A4zVEXMXCYhxxkcrdyT0C0zRFLHouyjidqZgnudQ5x05RVHtPqJ++rkB37NhORn6zse9Y+j6B/B+tj1xre610GpJGmWh07TVTmVVQXb89Y4HMcROCWH2nd42KrX8QNJcValjtetfpfULYxDT3ejD5aFzR9VksBJdGB95h7ySFvTqzd1PrRdryS1a5Jcu1e692RyglrHR8Ec7rqqprq2etrJnz1NRI6WWR5y573HJcT4kkqwtm1poe/wClBDUV0EVTbanekudHIJqSpHcWSN28djg+S1legpzhOKlB3RSkmnZlWhznBrQSTsAAtg1Bo3UNjpY6uuoHervaCZIzzhhPc7HQ/gpzhDYoaq4zahuWGW61gyFzh7JkAyP6o3/qroNruUNZcKrVbNUtfp50fJPSTMwIXgABuD065265HVc3FbQlSqZYK6W/fve5K3E9RsrYNPFYbpK0mnJ9XVaRW+TTaur8u813hNx61fonsaCtkN9srMN9WqXntIm/zcm5GNvZOW+AC78xvCXj1bjNTSNpr42PLsAQ1sP6TekjRtv7Q8wV5Ot+n6jWOp7gbDTR01H2r5GueC2OJpJ5QcA4J8B59wUdc7dfdJ3mPtxUW+sidzwTxSFp26OY9p/Uq2K2ZhsTO9N5Ku/T5o5cY4rD0+lyt07tKXB9zOn8UuC+qdGGWr7D6UtLckVtMwnkH84zqz37t81yuel8l3nhR6TNztwitevad10pMBouEDQJ2Dp7bdhIPMYd+kV0PU3Crh5xRtLtR6EudHR1Mu5kpRmB7uuJItjG7p0AO+SCubKviMFLLio6fiW716sWqWIp1loeNZ6fyWDNTkdy6XxA4f6k0ZXerX22yQscSIqhntQy/ovG3wO/iFpk9L5Lo0q0Zq8XdG0qZrksGCdljSRYU9NTHwWHNTqxGZXlTIZ8ZHcrTo/JSskGM7LHfD5KRSIXAjyzHcvktKznReStmI+C2uaZTELVTlKyjH5Khj8lm5jKY3KqEFZBjXwWeSzcxYtY8lTCuFq+S1ZMWPhF9FUIQwUREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAVQgVQMoCoX0AjQrzGZ7lhs2SPlrMq4yPyVyOM+CyY4s4WjkSKJjtiJV1sPksuODPcr7IFo5kigYDYFcEHkpFlN5K62mPgtc5IqZGNgPgrjKc+Ck203krrKbyWrmbqkR0dP5LJip/JSEVL5KQt1sqayqjpaSmlqKiVwbHFEwue8+AA3KjlUsSxpEXBS+S2TSGkr3qe5tt1its9dUHqI2+yweLnHZo8yV27hh6OtdWCO5a2ndbqUe0KGFw7Zw6+27oweQyev1Vs2tONPDzhhbH6c0FbqO5VkWW8lKcU0bumZJRvI73E9MEhc2WNlWn0WGjnl5LvYnUhSV5Mt6G4E6X0jbjqHiLcqOoMDed8L5ezpIf0nHBeengO7DlA8T/AElqSip3WThrQRBkbezbcJoeWNgGw7GLHuwXDH5pXBtfa81br+5es3+4zVQZl0VLGC2CEY35WDYbd5323KkNKaTtLdOt1VqisfHbi4iKnhB55SCRgkdMkHYfMKzDZUKdq2NlnlwS3X5W4/ArUXXx03To6JK7b0SS3tvgiClOqNb32aqmkrbzcZBzyyyP5yG+ZJwB4Dp0AUvw70zatSUN1pJppY7xFHzUzS7DMeJHU74B8irw1Fp2w6xobrpSKqjonRhlbBJnGD1AyScjY+GQMbLddY3eh0aynvNisdLN9KydrLWZODnDiPEcwyRvjY7FXsRiKto06ccuZdXhZren4HT2bs3BxzV61RSVNtT3tNNWi42V973vcyP0VDDqnRU2jrhNPQVdtmxIIzhzmBx6jv3LgfPlK1K7X2x2a/2+bSNDPAbc9wlmncQanuIcDuO8d3XoMKa1hfrZatYW3VunayGeSqh5qula7GQQPrY6EjG3cWgrSa6Su1TqeWShtjn1lfNllLSRueXOPcAMkk9T7ys4Wi5SdSSag9bcm9HdcezgZ2rjo0aUaMGnVg1HMlduK1g09yfBpam+XLX+l6erfe7LYHPvk7PbmqBhsZxgnYnJ92M+K1CxWHVGvdQVH0XQS19XI4y1MuAyKIHcue84axo36nuWwzaU0toSMVPEu5umuQHNHpq1ytfUk9QKiUZbAOmRu7B2Wo654n33Udu+gqCGm09pph/J2i2gxxHzld9aZ3TJceozgLWnOFPTDK/5nu8OfhZdpysZjsRjbdO0lvsklq97duL4t6m1VVZw64ebE0uvtTM+wwkWikf5nZ1SR5YZuVz3XGtdS60uDazUNzkqREOWngaAyCnb3NjjbhrBjHQdwyteaHOcGtBJOwAC6VZ+F7LXboL9xNu37lLXK3ngoyznuda3+ag6tB6c78AZHVaTcKbU6rvLz8F9PEqxXCK0NBslpud7ucNss9BU19bO7EUFPEXvcfIBda01abNwcu0N+1XqOqm1RT7xafsNXh8Z+7V1LctY09DG3mcchQV74omgtk2n+G9qGkrPK3knqI389xrR4zVHUA9eRmGjJG4XNicnJJJPU+Kw4VK6tPqx5cX38vD3mbqO46xddfcPtc3Con1xog2Wrnlc9tz008RvAJyBJBIeSTHe8FrjhYY4bafubxPo7inpmrGcthur32uoB7gBICwn3P8AcuZIsrD5NKcmuzevP5MZ770drotC+kBSRhtnu9zkpx9V1v1VEWEeXLP+xW7noDjdXRluqNQvpac/Wfd9Vw8nxBmJ/BcYRa9BUve8f+P6jMu33nTRoTQNi/Kau4n2+qc3c0Wm4H1skniBM4MiafiVMaY4vaV0Ndozofh1SspA0x1Fbcqt8lynaRglkzMNpzj7jSuNIsvCqatVk5eS8redwp23HWLroS16+kqb5w1v9Tdq+TmmqrFdpQLm09XFjyeWpHXcHm6ZBK5bW0tTRVctJWU8tNUQuLJYpWFj2OHUEHcFfFPNNTzxz08r4Zo3BzJGOLXNcNwQRuCF06i4lWvVNJFaeK9okvTWNEcF9oy2O6Uw6DLj7M7R91++53WbVaO7rLzXyfx7xpLsNa0FxC1NowywW2piqbZU/wB12utjE9HUjvD4zt/SGHea6Ta9OaN4m2uouejZ4tL32BwFTZK+ozTSF3R0Ex3aCQQGv+0cZG2dM1Twvrqe0S6k0dcoNXabZu+roWkT0o64qID7cR677t81quj706xXuOscwy0rwYauEH+Fhd9Yb7ZGzh4ODT3ImpXqUHZ+tGvrr2m0YxbUam43ymrtX8N7zPabjQTUbubM9DWR+w8HbmHvA+s04OB1Cnn6jotU2+DSOnrZFZvpCbnq3Oc0Rt3Djy4+sTgdw6Ae6PqNe1+mpGaa1PR0+s9HytEtDFVuIlgicAQ6mnHtx7EezuMYBA3WW7h1R6rs02ouFlfPeqOJ2Ki1VLQy40jsZxyj2ZhjOHM677bFbOdKUlKsssuEvut8G/195coY7F4aDoJuUNzXG3FJ6tJ8be424Wqmda4NMaUr6MUsFSGXfll/fDm5HN08dwfgB4LU9cQT6x4psslK49jStbC946MaPakd8Cce8BaxojUD9Iagmqqi3GeTkdBJG8lj4zkZ6jY5G+R4ratI3626e0jctSGqp6u/185HYk+0wlxIyOvL1cSOuw6qN4erhpuUes9yfbLe33HcjtDC7SpRpT6kb3mr6KEFpFd7e5a3uzW9X2CjbrZ9i0uyeqcMMMbnA4kwS5oPgBjOfArC05qDU+h7+6rs1dV2m4Qu5ZWjbOPsvYdnDyIIXVqS7Wmk0w/X9TY4aC5TQujYAf4dxOxA/OIznGcA9QtK0npZl6iq9U6tqZaegkc4hwOHzvccZGx2ydsDc4AU9HFp02qy6q011bfFcmUcfsWMq0fZms07z00jGHBu+qO68O/SI0zqugGnuJdtpaN84Eb6gx9pRzfptOTGem+7e/LU4j+jzQ3GmN64eVsTo5W9oyikmD45Adx2Uue/uDjj85ecOIWmW6WvTKJlYKqOWPtWZbhzWkkYcOncVKcMeKer+H1SPoavMtAXc0lvqcvgf44GcsPm0g9M5VGeyE10+Ala+tnuf09bjlSrVsHVlQxC1WjI7UNguVluMtvu1BUUVXGfbimYWn379Qe4jZQk1L5L2JpniLwu4022Kx6moYaC7uGI6aqeGu5z3wTDGe72difAhc74o+j5fbGJa/S7pL3bxlxhDf3zGP0Rs/8Ao7+Sq08c4T6LERyS7dz7mXYThVV4nnOWm8ljSU58FstTRPY90b2FrmkhzSMEHvBCw5KXyXSVQ1lSNffAfBWzB5KdfS+SsupfJSKZE6RCmDyXwYT4KZdTeStvp/JbKZo6ZDOh8lbdFjuUu+nI7ljyQeS2UjRwIt0eO5WnNwpGSLCx3s8lupETiYZC+CMLIe3CtOGFumaNFsqi+iqFZNSiIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiqOqAqF9tC+QrjGrDMo+2NysiJme5fMTMnosyCPyWkmTRiVhi8lnQweS+qaFbLo7TF31Neqez2SikrKyc+yxg2A73OJ2DR3kqvUqKKuyzCmQkVMT3Lb9IcOtYapDX2HTtdWRHYTBnJFn/GOw38V6i4ccC9HaHtn05rOaiuVbAztZpapwbR0wHUgO2OPvP8tgofX/pV6IsD3UGlbdUaimi9gSMPq9KMbYDiC448m48CuNLaVStLJhYZu3gSOUIbznNu9GriJURh04s9GT9marJI/qNcFdq/Rr4g00ZdEbPVkfZhqyD/AK7WhQ119LjiJUSn1C06eoovsjsJZH/EmTB+S+bZ6W3EenlHrtr07Wx/aBp5I3fAiTA+Sz0e1HraJp7TBEJqfhxrDTDXSXzT1bSwt6zBnaRD/wB4wlv4rXmwNC9JaB9LHRt6lZRastVVp+ST2TOHes0x/SIAc3P6JHiVvl3oeC+n4I+JFVT2OOnlANPVRHtIpndQY42ktc/Y7tbnbKieNxFJ5K1J3e63H14k8a8GrnBeGHBLU+ruyrquI2a0uw71ioYe0kb+YzqfecDwyuwXC78JuA1udBE1tVfHM3jYRLWy/pHpG0/0R4Alcm4s+kpfb521s0XHJZLectNW4g1cg8iNo/hl3mFxOx2+t1JqGKhbUNNVVvcXSzvJycFxJPUnY+9Xaey6+IXSYyWWH4V8368CnPGSqzVKirtuy7zfOK/G3WGvTLRun+ibM7IFBSvID2/zj+r/AHbN8lp1s05L63bX350tpttcSWVUjNsAZ6Z2ztgnxzut8t+ltC0d3/cnXyVVXeJozmocDG2N3LkBu+Mkbj63Tr3K9ZqQ3qwXTh9dpG/SVrJNHK7vaPqOHkMgfouCvxxNGhTyUI5Yrs4PTMuevM6VDYNRzvXkpS1SSd1njq4StubV7WfiZVH9E0eg7lWcP4oJainyyeWeLnlkaBlx38twMY26LX+FlwpLzZq3Q91eBHUNc+kcerXdSB5g4cPc5QfDu/S6S1U+G4B0VNI409axw+oQcBxH5pz8CVDamktrdS1c1glkFH2vPA7lLC3v9nvABzj3Bbxwjcp0nfW0lLjfv7OBJU2vFQo4mKSy3hKnuVnvsuTW/tSN5otI2vSloudVrCWhllmidHRxMcXPzgjmaPE7d23iFpc+prtNpeLTkkkbqKJ/O3LMv65Aye4HOMePgpXS+jNS6xZNeJ52Ulpg/uu83Wfs6aIeBkd9Z35rcncbLNqtcaM0HmDh9Qtv98ZsdRXWnHZxO8aamdsO7D5MnY7LZzjTk1J9JO97cF9Pj2HKr4zOlDDR6OFmt93JN3d3x+CKWjh4aS1Rah19dY9J2SQc0PrDC6srB4QQD2jnb2jhoyDuFh3vivHaaGay8MLU7TNBI3s57k94fdKxv58o/ggdvYjx71zzUF6u+obrNdb3caq41sxzJPUSF7j5ZPQDuA2Cz9E6O1JrO5mg05a5qx7BzTSbNigb96SQ4axvXcnuWlW81mry05cF9fH3IpRio6RRBPe+R7pHuc57iXOc45JPeSVueiOGt+1Lb3XypkpbFpuE4nvNzf2VOPzWd8r+uGsB3wNlsPJw34c/wrqXiFqhn2Gkiz0j/M7OqiPLDN1pWuNaak1pXtrNQ3OSpEQ5aeBoDIKdnc2ONuGsAGOg7t1p0lSr/LVlzfyX19zN7JbzdHa20joJppuGVtNwu7fZfqe7QAytPjTQHLYvJzsu3PRc1vFzuN5uM1yu1dUV1bO7mlnqJS97z5k7q1T00059hm33j0UhBbombykyHw6BT0MLZ3W98Xv9eRHOrbRkWxj3nDGlx8AFkxW+of1DWfpFTDGNYMNaGjwAX01rnODWtLnHoAFdjh0t7IXVb3Eay2Dq+YnyAV1tupx1Lz8VsdNpi/zxCZtqqI4j0kmAiZ/WfgK5+5yVn903iy057wa1shH+j5lhSoLS6+JMsNimr5XbusvM1oUFL/Jn+sUNBTHow/1itl+hbc3aTVVoH6LKh36ok+hKB20eqLO7yc2ob+uJZz0uXk/oPZa3Nf8AKP1NXdbYD0dI34q0+197JfgQtt/c1UP2pbnZqk9wZXsYT7g8tKs1mnL7SRdrNaqrsv5VjOdn9ZuR+KxehLS6Dw2Kir5Hbna69+41CWgqWb8gcPzSsZzXNcQ4Fp8CFsZG+F8yRskGHsDh5hZlh1wZCqz4mFpbUV80vd47vp661Vtro/qzQPwSPAjo5p7wQQV0H6e4f8RPY1dRxaO1G/perbBmiqXeNRTj6hPe+PvJJC57PbWHeFxafA7hR88EsJxI0jwPcqNbCXebc+a9eTJ4VU9EdWvugtR0GmPoW8QRVUMTXVNiu1HKJ6Ssi3c+NkrdtvaeGnBwXkjooLg1cp6a/wBXYmTzUzrpCY4HxvLHx1MeXxEEbhxIcwEffWDw74j6q0LO4WaubJQSuBqbdVs7WkqMfejO2dh7Qw7bqui3HTWi9cGg1VoW6xaS1DUvEjbXcJv3pJUtOSyGoP1H8wBDH/Wy0gjKqylOnFxqLTg181/tdxcpzvJTXDf2rd8NCKj4jWnUMrrNxYtUlXUwnsY9RW5jY6+PGw7Vv1Z2jbrh2M4JKs6n4d3G32f90mn62m1PplxPLc7eCRFjflmjPtQuAIyHDG43UPx205cbFq8VFwtc1tkr4Wzup5G47N5HttGNiAcgEbHGQvrRGq9Q6W0JJctOXSot9VR3Qvc6M+y8SMYOV7T7L2nszsQRspqUpU0pUHo+D3eHLw07CGpQTlKMt648zPpdUMvVZZ6LVkh+iaAY5aeLHPtgcwB6bAbDpnHVdCsl4sOurzT0sVPW0ws8vrFNGCBDIxpAaSO7G2B79+qh9SVHDjU9bR0d3Eei9R1NDT1Dq+niJtlRLJGC4SRjeD2ifablveQtXvFl1pw3uDJ389NFVM/e9dTPEtLVsO4LJBlrxjB8RtsFrKnSxCtDqTtouGu9rnf0kdTB7XrYSrlxCzwbWZ2vJ23K75W0Njt1FHrDifcrxVlv0TbJN3OPsuDNmj3EguPlnxWj65u8N81PWXCnhjhge/EYawNLmjYOPmep962vQd6slTo6q0jX1r7RPVPcfWwByyZI2cT02ABzjbvWjX23i13ept4qoarsH8nawnLHe79R9xVrCwy15KWmVJJdnPxNdqVs+ChOm088nKb0vmd7RtvSS8HvMLouycJvSC1Zo/sbfeXO1BZ24aI53/l4W/mSHcgfddkbADlXGl9Na5zg1rSXHYABW8ThaOJhkqxujzsKkoO8We2JLdwo47W59daqllNegzmkfG0RVcR/nYztI3pvv4By4XxM4Sap0Q+SeqpfX7WD7NdTNJYB+eOrD067eBKwyYeD1nj5WRy8QrhBzEvAcLHA8bAA/wDnDge/6oP9bs3D7jJctP6Foqvi9LAw3AtFtbFDmsqIDs6aaIbCPwdsXYOAep8nPDV8L18M88G7JPe+7s/3a2p2KOM+7PeeY3QMPRbXprhXrjUkbZrTputfA/ds0rRDGR4hzyAfgvU9Bb+C9ooH8SKeOwQUMw521zn/AJFrvBjHHDH525WtDsgjGVzLXfpd6eoJpKXSGn6q8FuWiqq3+rxHza3Be4e/lKjWNxFd5aFN3W+/D13+BZnXglc1Sm9GjiBOwOklslMT9mWqcT/qsIWHdPRt4jUsZfTwWuvI+zT1gBP+kDQoqv8AS04mTyl1PQadpGdzWUsjj8S6QrMsvpd69p5W/StisFfDncRslhkPudzuH+qpMm1FraPcQ+0wOf6s0PqfTEnJf7FXW8E4a+WI9m4+Tx7J+BWsy0/XZex9Bekxw51kwWnUlO6wT1A5HR3DllpJM/Z7TGP67WjzVnix6PNkvtJJeNCOht9a5vaCkDv3tUDGRyH7BPdj2enTqkNpzpSUMTDK+fD17zdOM1oeMZocLCmixlbXf7PXWm5VFtudJLSVlO8slhlbhzD5j5fgoOpix3LtQmmroinAhZWYWO9qkp4/JYcrcKdMrSiYjgvgq88bq0eqkImj5REQwEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAFUKiqEB9tCvxNVliyYgtWbpGTA3KkKaPpssWnbnuUpSMBwoJss04kpYbZVXO401voIH1FVUytihjZ1e9xwAPjhe2tFae0rwJ4Y1V5vlRE2pbEJLjWAZfK/wCzDGOpGTho7zknHdyz0LtGR1d1rtaVsPNHQ/vWiyNu1c3L3e9rSB/TK596ZvEibVWv36UoKg/Q1hkMTg1201V0kcf0d2Dww77y4GIzY7E+zRdorWRNUn0cTTeN/GHUvE+7uNXNJQ2SJ+aS2Rv9hg7nP++/zPTJwAubIqgFxDWgknoMLv0qUKUFCCskc5tyd2dH4J8NZdb1ktfWPEVno5A2Tch078A9mCOgwRk+Yx5YHGDQFXoW/cgPbWurc51FMOuAd2O/OGR79j4gen+Gen36b0daLW+NsL4aQGoaw/Wmf7Tydu47A+ZUdxxgpqnh3cGTU0VRPC1tTAySAyDMbmucBgHBLeZufAnuyuFHac3itPsvS3zPYz2FSjgLvSaV7/L5Hjhbnw24hXTR0k1DJDHdtPVvs3Gz1RJgqG95H3JBth7dwQOvRV1jw6vmnbZ9KyRtmowR2oYcvpw76hfgYLXdA5pLSQRsdlpa7idOvDTVHk6tKpQllmrM6rxB0vbqGiotV6UqZa7Sl1JFLLIPytJKN300wHSRvd95uCFqdHUz0lXFVU0hjmheHxvHUOByCti4DX6kF2qtB3+YDT+pw2lkc7pSVX+AqG+Ba/DT4tO/RQl7ttXZrzW2mvi7Krop308zM9HtcQfxBVrCVXK9Kpq15r68H7+JTqRyNTjp8mdlrb9HV6MGt7PaqKe7RRCKd8jcugAzzYHXYnP6JyfBclo9R3am1K3UPrHaV/ac7nvGz9sFpAxsRtgfBY1tnu00Zs9ufVyNrHtBpYOY9s7oByjqfL3LdXaM0/oyBlfxQur6WpLQ+LT1vc2SvlHUdqfqwNO31vaxnAyoIUqODUlPXNuW925d3kdjH7Xr4+VOUG4uKTfBZvxd77TXrdbNT8QNUSi2W2W4XGoPPIIIw1jB05nH6rGjA9px95yp+qHDzh3n6Vng1zqVnSgpJSLZSv8A52UbzEHHss9nYgla1rTileLza36dsNHT6W0z/wDllvJHbDxnlPtzO6Z5jjYbLn4GViUqlVZX1Y8lv8Xw7l7zmtXk5yeaT3t8zZ9ea81NrWpife64GlgGKWhp2CKlpW9A2OJvstwNs9fElQNqt9fdbhDb7ZRVFbWTu5IoIIy+R58AAMlb9YOF0tPaodRcQrqzSFjkHPC2dhdXVo8IKf6xB29t2GjIO4V668T4LJb5rHwutLtL2+VvZz3F7xJdKxv58w/gwdjyR4A33KgVVJZKEb29y9dnjY3s98mZDNCaW0KxtXxRubqi5gczNMWmZrqjPUCpmGWwDploy/B2woHWvEu96htgsNvgpdO6ZjOYrPbGmOE/nSn60zthlzydxnAWkvc573Pe4uc45c4nJJ8SrlPBJO/kYPee4LeGHvJSn1n5LuXp9phzstNEW2Mc9wa1pc49AApOkt7W4dPhzvu9yyqWmjp2Ybu49Xd6kLZb6y5VYpqKB00hHMcbBo73EnZoHeSulClGCzTK+aVSWWC1fvMQAAYAAA7lKWyxXCvgNUGx01GDh1VUvEcQ8gT1Pk3J8lml9lse0TYr1cB1e4H1WI+Q6yHzOG+TlFXS5190nE1fUyTuAw0OOzB4NA2A8gFtmnP7Gi5v5L6+4l6KlR/mu75L5v5K/emSX/gzbtv3zepx35NPT/8A1u/1V8v1Rc42llu9XtUZ2xRQiN3xf9c/Fyg1sunNC6rv4a+3WaoMLtxPL+Tjx4guxn4ZWlSNKms1V+9+kSUq+IqSyYeNuyK19+9+LNfqaioqZTLUzSzSHq6RxcfmVaXZLLwGuk5b9KXqngcd+zpoXSu92Ty/qK3e1ejra+VpmjvtU784tjYf9XP4qlU23gqWma/ci3HYOOn1qiUb/iaX6nmRF63h9HexBozp+pf5vryP1OC+aj0d7EW7WGrj82V2f1uKr/8AqPB9vl9Tf/0/V/8Alh/y/Q8lLIoqysope0o6uemk+9FIWH5gr0bd/R1trWudA6+Up8XNbIwfJo/WtIvfAq903MbXd6Os5fsTMdC8+X2h8yFYp7awVXTNbvXpGkthY+n1oK9uMWn+pz4anrZxy3amors3vNTCO0/0jcP/ABVRBpy4/wBz1M9nqD0ZU/lYCfJ7RzN+LT701FpDUunyTdrPVU8Y/wAKG88f9duW/ioFXoQpzWak9Ozd9CnUr14SyYiN3+Za+/SXnYkbrZrhbAySqgBgk/g54nCSKT9F7cg/rUc9rXtLXAOB6ghSFpu9fa3PFJORFJtLC8B8Ug8HMOxUiKez3z+4jHabif8AzeR/73mP5jzuw/muOPMLbPKH293P6r14Gio0638l2fJ/J6J92j4K5ptXbur6f+pn9SkNIVUUhqNPXBwbSV+Axzv8DOPqO36Z+qfeCfqrIraWpoqqSlq4JIJ4zh7JG4IKwKykZUDOzZO53/FaVKCks0DSFWVOVpI6ho7W9SNC3PSGtbPDqqhs0olbSVr3CeGA4a4wTD2o+UhuOo/KYxhfVLoSzaj0JqCThZdKm99q+nqH2WrYGXGkDO0LhgezMMEYczwxjK1SyVhqKyjvEzSZ2YoLq3Ge0jkHK2bH2j0d35czPgp6zcNtc6bqbm2agrbXJU0xfbnt5zPzNkbyP5Yg58Y+thzgNxtlcipTjSd4yytvwfh80dKKc7ZVfRry9LwNH4oiSPVstLK1zH0sUcDmuGC3kGMELqGltS3zTFZZOH1J6pVWiGlM+oKK4U7Z6c8xMkuWncPbksaQQS5rPFT9Td6HVOs5IuJGlo6umopw+C+07BBXQhjQ9sc8bgO2YfZGHNBw7IPeta4j6QvNi0lctRWCp/dLQ3mYS1V2o4yHU9NgOjZNGfbiJBDncwxnl3y1aympqMKqtfdy70/hx1N7KMpylz+HDxdvcy3LYNB68rJW8ProLLeecgWG6zgR1B8KWoOzs7Ya/Duu60K+Wi6WK5y2y8W+ooK2E4khnjLHDzwe49x71p3TcdV0vTPFeqNsh0/r22M1bY4xywmoeW1tGPGGo+sMbew7LTgDYK7CrVo7utHzXc+Pjr2nMlTjPVaPyNXXSeEVHR2K1XPibeKeOensz2wWqnk+rU3F4ywHxbGPyh9zVj1WgKO/2+a9cMrsdSUUbeee3PYI7nRt/PhH8IBt7UeQfBZ/Funnt40pwvt8ZdNa6WN9XE3rJcKrD3g+OA6Ng8MFSVMRDEJUoPfv4NJb78r6LxuRxg4O7W4taGpaeVl24q65DrlSUtSRT08x/vpcH+0Iz+Y367/LA36L7pexucVdxa4pTTVlDJUGOioWu5JLrUN6Qx/cgYMBzh0A5RupPWNp/dBxH0/wjstQxlssI9SlnBw3tsdpW1Jz4EP690YXMuMuroNV6r7O0sNPp20x+o2amB2ZTs2DyPvPOXuPXJ8lVc5Tay6OS/4x4JcnLf8A6RJGNt/Dzf6EdxB1xftb3RlXd52R00DezoqCnb2dNRx9zIoxs0AY36nAyVrKLsPATQ9JdbfU6iuUAm56ltBQscMgPODJKAepYwkt8we8BKtSnhqV7aIuYXDTxdVU47zR7/o6ay6Hsuo6yta2a7veYaIxkOETeknNnvy3bHRwWrLq3pQVLncQoLawCOloKCKOGNow1oOScD5D4Bcxt1FV3GuhoaGnlqamZ4ZFFG3LnHwACYapKdJVJ8dfA3x1GNLESpU1u073x97Mddk9HzjpfOHFwhtd0lnuWl5HYlpXO5n02Tu+EnpjqWdDv0O63Hh9wJtdNYJ3atBqblVwloZE/wBmkz0LSPrPHj07txueG8Q9IXPReopbVcWlzPr09QBhs8fc4ftHcVX6bDY3NRevrgS4jZuKwdONaasn5d57e43cPrPxV0TBqvS74Km6NphNRVEPSsixns3Hx68uehyDjJXimugfG9zHtLXtJBaRgg+BXePQX4kS0t4n4cXSoLqWrD6m1l7v4OUDMkY8nNBcPNru9yxfS60XHp3Xzb1RwhlFe2OnIA2bO0gSD45a73uK52DlPCV3hJu63xfYZhJVI3PPdSzfoo+duFM1bOqjKhvku9BkFSJHShWHLKlCx3qZFWRbPVUVSqLY1CIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCqFRVCAuxrLhG6xY+qy4Oq0kSRM+mG4UvRt3GyiqXqFMUfcq8y5TPcHDF8egvRlivXI3tKe0T3V2R/CPc10jR8RyN+AX58VM8tTUy1NRI6SaV5fI925c4nJJ95yvfHEgvb6G7+x6/uYox17uSIH8MrwvpSioblqS30FzrfUaOedrJqjGezaTuf+/u6rj7GtatVe9y+GpHiE5zUUbPw+4YX/WVsluNIW0lPz9lTyzMPJLJgkgkbhoxjmAO5A8cdo4ecD7JYKqluV4rZLnc6eRsrWMw2BjhuPZIy7B7yfguh2imt1HpunhsRdDbaWP97ij5JBKwDPsnDs5OfMlZVJXvluElKbfPF1f2hA5S0YAJ7wXHmwOuGknGyqYnaNerdRdl5ntMFsTC4fLKazS58L9iJBoONzk+OFh3BtzM1KaCWkZEJf3y2aNznOjx9ggjDs46ghZiwaJ9zNyrIqyGnFI0tNJLE48zwRuHgnYg+Gx6+Q5keZ3Z8EarxZ09cdR6cNnpGtMVaBFUSA8vZOBD45MdXN5xykDueT3LmFs4BU9JaX1GptQGKrka5kUVGwuYJC32NyOZ+4OWgDPQFeg6qnhqqaWmqIxJFK0sew9HNIwQtSs89ytV4GnrnBV3SGmpY56WvYAXcnMWFsgyC5w5WEkB2c5V3D4urTpuEHbicrGbPw9WsqlWN76di8F6ueRNQWO7aeq4YrlTvp3SsE1PIDlsjM7PaR1Bxt8F33XOk6TVlRZeJF91FbdPWS92iknraud3NJJWBnZzRwwt9p7ssDj0HtZJ6qK9Ii4/TekhNPQQMq7PeX0E0zZc7uZztDCMgtcwNLgcFrgBhabxNPNwg4VufntPULgD+iK2Tl/au9Sr1KipzTyyd0+Olr/JHhsfhKeHqypxd46NHWdLaktOg+PlBwz05p+Khp/pD6NuF3qXdrXVZkaWtLH4AhbzOaQ1g3wMnqF5ovUVVBea2CtlfNVR1D2TPe4lznhxBJJ3JJyuz6/Lx6ZVvcwntTfLQTv9vlpyfxyreuY+Geh9bX2vr3M1xqGS5VEsdujJjttETI4hszx7UzxkZY3DdiCVpQqZJKVm5Sinzu+/xK0lpbgmaDoXhzqHVdLJdI209qsNOf3zeblJ2FJF4jnP13fmtBO4WynVuieHw7Hh7bxf76zY6ku1OOSJ3jS0zshvdh8mXddlp2utdal1pUxSXyv5qenHLS0UDBFS0regbHE32WgDA6Z2GSVrSt9DKrrVenJbvHn8Ow0zJbiSvNzvepbrUXS6VdbdK54Mk08rnSP5R1JPc0fIKNWVb7jX24zmgrailNRA+nnMMhZ2kTxhzHYO7T3g7FY8THSPDGjLj0ViKtoloaNn3TQvqJeRnxPgpuCJkMYYwbd58Vlw1tUywQWUyMNJDO+oa3smh3aPa1rjzY5iMNbsTgYWbYbW2uMtVVzGmt1Nh1TPjJ36MaO97t8D3k7BXKcVSjmkRKMq01CHr9ClltLq9slVUTNpLfBjt6l4yG+DWj7Tz3NH4DdXrreWOpDa7RC6itufabnMlQR9qVw6+Tfqju8VZvt2dcXRwQRCloKfLaamYdmDvJPe497j19ywqGlqa2ripKOCSeolcGRxsblzj4ABbKLl16nu5fqSyqqmuiocdG+L7FyXZvfHkrC3rQfDHUGqBHVPYLdbnbipnacvH5jervfsPNdW4PcExHPFW3umZX3HZ7ac7wU/m49HOHy8M9V6WsGl6K2hsszRUVA+04ey33D9q85tL9oo0m4YfV8/odfD7Ip0IqpjXrwgt/i+HxOPcOeCFotjY6iK2tllGD65Xjmd72NxgeWB8V1226PtlMA6p56p4+/s35D9pWxovIV8XWryzVJXZeljpxjkopQjyWnnvLNPS01Mzkp4IoW+DGgK8o3UN+smnbe64X67UNspW7GaqnbG3PgOY7nyCgdA8StFa7qaun0pe47k+kwZuRjmYB2zhwBx5qJUpyi5pOy4lPrSd95uCKC17fXaa0jcL5HTtqH0rA5sbncocS4NGT8Vn2Cv+lbFb7p2Yj9cpY6jkznl52h2M9+Mp0UsnScL2NMyvYzljVdFSVbcVNLFN+mwErUdZcVNBaO1BBYtTahp7dWzsEjGyNcQGk7FxAIaDvucBbXaLpbbvQsrrTcKS4Ukn1J6aZskbvc5pIR0qkEpNNJ8TdOUHdaMgrpou3VLHequdTl3Vp9th+B3/FcX4kcCrTWNkqG0P0bOdxVULfyZP50fT+yfNekVQjPUBT4fG1sPLNTlYue2ynHJXSnHt3+D3o/OjXPD/UGknulrIPWKHOG1cAJZ5c3e0+/4ErUl+jmpdHUNxhkNLHHFI9pD4nNzFID1BHdleW+LvBWWlmnrtN0roJ2ZdNbj0d5xH/5fl4L2Ozf2ghWtCvo+fD9Pgc7E7HhVi6uCd7b4veu7mvM5LQXenrKWO2X9sk1OwcsFU0ZmpvDH32fmn4YWDebVUWudjZHMmglbzwVERzHM3xaf1jqO9YMjHxyOjka5j2khzXDBBHUEKYsFzYxhtFxjdUW2oeMsBHPC87CSMno4d/c4bFd9xdPrQ3cvp61OXGrGuujrOz4S+T5rt3ru0Oj+j9pugNfT6nu9fJRUVNUNfUTskcwtYwh4iBbu6SRzWey3cMDicZbzdX4hcQ9KV+on3ekqLzS1DqWOldmWnijkbG+RzTh7Hkbyv/DZcN4l6sZb/VtPWGP1ako4xFBHF7JA6l3k5313O8x5Bc4fJWSvL5akBztzyMB3/ScCT81zpbMp4ip0te7fLgkWI4x4ayp6NcfidoqpRcpq2sFXFWVFTK2Zz5AxzedrWtZkNABAEbcjG+CoDiDXV+lr/FrjQVwuVnqHMArYMktZuAA7OWPYSR7JLuvQLnEFRXUsglp6klzemWhjvg5oB+eVvFnvY1Hpi6W+saHVLaWQe03f6uxI6ZaeU7eIKt1cLTmkrWsrW4NcrGY4x1YyjLVvW/G/68Sz9J8OuIvs32ng0JqZ/S40cRNsqn/z0I9qBxOPaZlu5JC1DXeg9S6LniF6ogaSo9qkuFM8TUtU3qHRyt9l2Rvjr4gLWFt+hOIuotJQS26nfT3KyVJ/fVnuMXb0c478sP1XdPabg7Ddc/o50v5buuT+T+W7uIbp7z64JU1VWcXdJ0tJUT08kt2p2mSF5Y9rOcc+CN/q8y7poDiDp/XPGusqtVaapG1Fnqau50l7o8xvZT03M9raiMbTBrWtAds7ZvVQ3Ai38N9Q8XNPag0pWyacudPUuln09cHmWOQ8jt6Wf7WCQeR/tbHB2XPuAxJqddPJPajRd0IPfnkaD+BcqVdqs5vVNRS5NXb9/mjeKsku06DPp6t0VoXXXED6at17hulCKC1XSimD2zvqpcTnH1o5GsDsgjILiF5zXSrWSPRnvnZk5dqujEm/2fVpyPxXNVdw+Zym5u7vblokiOSSSSC9b8BaOlj4R6dqZHiLsZJ6hziQAXF8rNyfJ34BeSF6K9G67Q36xU2mKyMSxWh09Q6J7csdzPYYiQdjhzpjjuIaeoCq7Wg5ULrg9fM7n7O1IwxTT3tWXfdEfx40pV6y1zaazSgZcjVwerzvhdzRRFhJD3vHsgEO8fseK6Xwp4a2jQ1CJWhtZd5WYnrHN6eLGD7LfxPf3Ab302C0/VfEXTemY6t1zrGOdCMxR07xK+V3ezA+o4HudjbfPXHD9prVqaoQWi8z1awOFwtaWKqtXfPcu42S83O32a2TXK6VcVJSQN5pJZDgD/iT3AbleU+NfEt2ua2Kio6RlPaaOQugMjB20jiMFxP2QR9keWc7YhuJfEC9a5ufbVrzT0MTiaaijd7EY8T9535x88YC1BdnAbNVD+JU1l8DzG19uSxV6VLSHm/0JbRt7qdNastOoKRzhNbqyOpaAevI4Ej4jIPvK90+lvbYLxwbF4hw/wBQqYKmOQD7En5M/A9o0/ALwAv0A4ql7vRLDpv4Q2e3F3v54P2qDayy16E1vvb4HJwj3o8SVjdzsompAUzW96iKnvXXgb1URs3VYr+9Zc3VYknVWIlSRbKoqlUW5GEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAFUKiqEBdjWXAd1hsWVEVpIkiSdN1Cl6I7hQlM7opajf03VeaLdNnufRcA156LcdohIdNU2KW3MH3ZY2OiZn4tafkvKXo0aRpb1qqqulfM0fRIHLSkkSF7sgOPkMO+OF3D0LNXsaLlouqlAc8+u0QJ6nAEjR8A0geTitA40Wqt4K8fP3V0NM92nr898zmMGx5iDNF4czXEPaPAtHivPUM9OpWw0XZy1X09xaoyp0sTTqVVeKev18De3aMuNtdcH6TvbrO+oqfWGRub21P7X12mJ2zd8kOYW9cEbb7Np113daIRfI6dtwaOWZ1OT2byNuYA7jPXHmrtnuNFd7ZT3K3VDKikqGB8UjDsQf2jfI7sFYWodT2DT8tLHebrTUb6uURQtkfgknvPg0bZcdhnqufKVSo8rV33anvIQpUV0ido9+mvkTCKkb2Sxtkjc17HAOa5pyCO4grR+KfEmz6HouRxjrbq/HZ0LZeV3KftuODyt/Wo6dKdWWWCuyWtiKdCDqVHZI3la3erXdpdRxV9E+KSnFJLE6OSUtOXFnM0EDIDgxpBH1SzO/MVx3hXxvr59RuotZ1UDaKqJ7KobEGNp3k5Acfud2T02z3ldp1Hqyx2PS0uo6muhloWs5onwvDu3cfqtYQcOJ/4norNTC1sPUUWtWUaOPw2NoucZWS381Y82ekJZrZZrza42SyS3iekEle/HK1wGGxuLckiQhp5t9yM96lOI1lkrtf8OuGcbD29Ba7fQVcYH8HUVD+2lz7hMM+4rA4fRnXPEi56+1d7Ngsg+k7oSfZ5GHENK3PUvcGsA7wHKQ4eXmslvus+N97IbPQiU0Gej7lVBzIWNB6iNpc/wAgxq73WpxUW7uK/wDJ7l64NHgcVUhWrSnBWTfkuPjv7zOs1TDqz0y3XMPBpIL/AC1fadwhpOZ4d7uWEfguL3qtfcrxW3GQEOqqiSZw83OLj+tdE4XA6e4ca215OSJZqX6AtjnH689TvM4H7zIWuP8ATC5grOHglNpbopR92vzRUk9PMLOtRtOKz6VFaT6s71T1Yt/h8jl7Tm+xjmzjfosFZ15ulZd6qOprnROkjgjgb2cLIhyRsDG7MABOAMnqe9Wmm9DUwVL2qm7OPtnj2ndPILAt8Hb1ADh7Ld3eam1aoQv1mQVZcDNs1vmulwjo4C1mcufI84ZGwDLnuPcAMlZeoblDOIrbbQ6O10mRC0jBld9qV/5zvwGAsq4H6DsbbWz2a+vY2atPfHF1ji+Oz3f0R3LXVJD+JLO9y3fX6dneTVX7PDol9p/a+Ufm+3TgZFvo6m4VsNFRQvnqJnhkcbBkuJ7l6t4FcJY7PG2aUMlub2j1qqxlsIP2Gf8AO/uUL6OnDKWkZFdK2AC61jMjnb/ckJ/U4jGffjxXqC2UMFvo2UtMzlY3vPVx8SvIbc2w5t0KT049v6HewWFjs6mq1RXqy3L8K59/wKWugpbbStp6WMMaOp73HxKy0WDfbrbrHZ6u73asio6CjidLPNIcNY0bk/8Ad3rymsn2kUpOTcpO7M5c09Jm+as01weu180dUNp7hSGN0svZiR7IS4Ne5ocCMjIOSNgHHqvLGvPSk1xcNfm56Zqfo/T1LLy01A+NuahgP1pTjPM7rgHDdhvuT6AsnHbh7rThJd7hfXOhDaR1PcrYBzSv7QFnKwd4dkgHp4nYrsfuvEYaVOpKGZNrTf4M0TjUg3B6rf8AXtR4N1Df73qK4uuN+u1bc6t3WaqmdI7HgCTsPILpHopay/cbxdoZp3vFFXNdS1AaM9Rlpx3nIwPeuU1UXY1MkQzhriBnw7lWiqZqSshq6d5ZNBI2SNw+y5pyD8wvaVqEalJ0mtGrFChW6OqpvXn3cfej3JxQ496E1JpC46es/wBKTVdS1nZvdShkfsva85Jdno09ykeHnpC8P4NO2Ox1jrtBWU9HT0ryaTmYZGsaw8vKSSCQcbLyNZ4tS3C6TXc6crYqF/avdMKSTsmFwdyt5sY3JAHvWFMzVlklZdnafuEFPvLS1UlJI2MjHsyBxGCOhBCovY+CdDo7vfffxsYVapnTe75Fzjtqt+tOK19vpeXQvqDFTjOQImey3HkcZ+KgdJ6s1LpO4Cv03fK611GfadTTFof5Ob0cPIghQamNHC3HVVqdeIJZ7YyrjfWRRAc74Q4F7RnbJbkfFX40oxpqmldJWsa1KrlUdTdc/TbhJXaguXDPT1x1UY3XmqoI5qosjDN3Dmblo2DuUtyBtnK2pcN4v+kVpHSOkqWq09URXa53CnEtFTtGBG09HSA7txvt12K4fwS9J/U1DrbseINyNfYbhJyvk7IB1A4nZ7cDJjHe05ONxuMHw8dlYmvGVZRstdPp3HSbjTSUnq/WvI9xKOvlppLtTdjUNw8fUkH1mH/nuWZTTw1NPHU00sc0MrA+ORjg5r2kZBBGxBGFdXK1TJITlCSlF2aPKnHnhG+tlmuNugZFeI28xDRhla0f/P4H4HxHmrElPUYexzJIn7tcMEEHoQv0vvtrgu1C6nmwHDeN+N2FeRvSN4cS00tRqOgpuSogP/WELBs9vdMP2+WD4r2GwtsO6w9Z9z+RnaGEjjabxNFWmvtJcV+JfM4xrAdpqIVzcugrYRJA/wCA5m+8Y/BRazaWta2lNDWQCqpC7mDC7ldG77zHDdp6LLpbTFXU9TPQXKMtpo+0kZV07u0azIGQYz7QBIycZ3yV65vLqzzyi6r6u8h1KaalFvF5u8h5YYKQwj8+Z2QGj5jPhhWmwW+P2qi5Om/Mo4Cwu/pvOR8BlQmorlPUujomQx0tDB/AU8f1R+cSd3OPeT5rSpPKrmacVF3uRCIiokpt/BW6MsvFzSlylcGxRXanErs9GOeGuPyJW68Lra2z+kXeNGVREUVe66WJxdsPykcrGfAuDPmuOMc5jg9hLXA5BB3BXWeMldUt1XpXizaCGOvlLT3DtGj2Y7hTFsc7fg9jXf01SxELzy/iTXitV8ySD07jE4cwS3DhdxJ0o+NwrqanprxFE4bt9VlLZ9vEMlJ/ormC7bqi6UmiuNlp4kW6l7fS+qIjcHQAZa+GoBZWU5xtzNc6QY7vZWg8UNJt0VriW38xrrRNyVltqWOw2so5PajeHY727HwcCmHqJyf5tfHc14WEo6dxThpoG865unYULDBRROHrNY9vsRjwH3neDR8cDdesNE6MsGkbdDSWikDJGNIfUP3llJxkuPfnA26DAwrPC246buWi6GXSsMdNQMbyertHtQvH1mv7+bxJ65z3rE4ocRLNoa3c1U4VNylbmnomO9p/5zj9lvn8srh4vE18XV6KKt2fU95s7A4XZ9D2ick3b7X09XZIanZPXXihtLKmGON8MtQ6nlzyVZYWDs3YOeUBxJ69W5BALT9V4tFVaXWjUFnjp6NzeV0U0QdTYHeHgcrR4Z5XeQXj/VWsL/qTUP03ca+UVTD+Q7FxY2nHUCMA+zj5+O63DS3HHW1nY2GtlprxA3b99sPaAfptIJ97sqxLZNaMI5Xdrw1KUP2hw8qks8Wk+O/TtX0Ny1jwDpKxjrhoi7RCN/tNpah/PH/QkGT8wfeuNas0lqLStSIb7a56TmOGSEB0b/0XjLT812ih9Img7JzarSUsTn5L+wqwQ4nYndoWmcQ+LEWpLPPaaKwyU8EwAL6q4zT478tYSGgjuyDhWsJLGxko1I3Xh9Tn7QhsupBzoTtLkk7e62nvRz3Tlrqb7f7fZaJpdU19THTRDGfae4NH4kL3p6VVZTWPge+zxENbVTU1HC3v5WESfgIh81wv0HeHk151lLruvgP0dZ8x0hcNpapzcbePI0knzcxTfpjavZd9YU2mqSUPp7Ow9tynYzvwSP6LQ0eRLgq2Ml7RjqdKO6Gr9e45WFhZXPPdYdyompO5UjVu3Kiqly7cEKjMKbqsV/esiUrHerCKsi2VRVKotiMIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAKoVFUdUB9tKvxO6LHCuxnBWGbRZI07sd6lKR/RQsDsFSNK7fqoJos02bjpG911gvlHebZMYayjlEsT/ADHcR3gjII7wSvZ5bpLj/wAJpKOsaI3PA7VrSDLb6oDZzfmcH7TSQe8LwvRSdFvPDnWN70Ze47tZKns5B7MsT945md7XjvH4juXHx+EdW04O0luZdSU1YtXr/pL4B3qs0/UBjqGq5jSTSRmSml7hLEc7OG2WnyyDsuU3a4Vl2uVRcbhUPqKqoeZJZHndzjv8Pcv0Q0bqnRfGrS1VarrZo53Rsaa231TOcMJyA9jx8cOGHDyXlXXfDThtLq272fTOtXadrqGslpjRX6Jxp3OY8tJZUxh2G7bB7c79VtgMZnlJVKdpre0r/DX5FTEuooxpyl1VuTZzjTnELWOn7ZLbbXfKiKkewsEbsPEWe9hcCWH3YWuVlVU1lS+pq55aid+OaSV5e522Bknc7YXR38DNfynmtMFkvcPdNb71SyMPuzID+CM4GcQ4zzXSjtFmh75q+80sbB78SE/gr8a+Gi21JJvuuQTnWnFRk20t285ktl0Bo6+62uhttoY1lPCO2rKuofyU1HEOssrzs0AA+ZxtldGs3CzQ9psF61FqTWceoxY4Ypqq26eB5X9pK2NgNTI0NwXOGeVpOASD0WPDVay4oW5+n9KWeg0joWhd2lSGPMNFABj8pVVDt5njbrk7DDVrPE3TyaW3t6JeG9vy7TVR5lm8SN1RPa+D/CuKSptEdR2tVWvb2brnUgYfVS/chYM8rT0aMnJWJr6phvdwsPCbh6HXC122fso5Yxj6Ur5MCWpP5u3K3P1WDOcFVvuprNp6yzaB4XCprZLjiC633sS2ouZJx2ELPrRwk42+s/bO3XNn7Hgxp6elbLHJxGutOY5jG4O+gqZ43YCP/OHg4OPqNPnvAk1ay14J72+MpevOyNvX6EPxrudvojauHNgqGVFq0wx8c9RGfZrK95zUTDxaHAMbnubtsVzdPMor9KmqcVEik7u4RFmW221tayaeno6ianpuV1TKyMubC0u5QXkDDckgDPeQFIYM62Q9lTBx+s/2j+xbHpSlgfWS3GtYH0Vuj9YlaekhyAyP+k4ge7KhgAB0U7dD9HaYoLa3aatPr1T+ju2Jp+HM7+mFdqK0VBcdPr65muFtndWW6OvjwXvtfsTIiuqp66tmrKqQyTTPL3uPeScldC4C6P8A3Q6k+k6yEvt9ucHcpG0s3VrfMD6x+A71zmKN8krYo2l73kNa0Dck9AF7c9H/AEZFZLNRUb2NJpGCaocB9eoduffju8mtXL23jfZMNljvei7uP0OhsbDqtWliK2sYavtfBeLOmaTtDbVbh2jR6zLh0p8PBvw/4qaRF85bbd2XqtWVWbnLewvN3p32jW900PbZLBHNUafpHyTXiCn3fkcvZvc0bujb7ecdDuemR6QJAGTgALjHEH0jdC6aqZaC2ifUNXHlr/Uy0QA94Mp2P9EOHmr+zIV3iFOjDM1w9birWlFRtJ2PzvUvpYXuS9wUeno6me4VZNPHBTsL3Tc2xZy/aB8FuHGi5aT1HeH3/TOlnaZfK4mqpWVYlgkcftMaGN7M+IG3gB37t6PXEHS/Cy3z3KTSE941JVZaaqSpbE2CLujZ7LiM9XHv2HQL3tSVZUrxp3lyuvN3sc6M4qV81u02Dgj6O1BdNZXCz8UKutpLvRwxVTbTA9oFRC8fX7YE8zQ72HBmMEfWXo9tv4K8I6dhfBpbTcrGczHzFnrbx4guJlf3+K8f8ZvSA1HrTUNFcLNTs05Jb45IoKmind6zyyDD2mUcpLfDAC5D2ddcppK2plkk53kzVVQ4kFx3Jc47k/Mlcmrs3E4xqVeo46axXP4dvEmjVjDSKPa/GLjpw41ZpWfTem7xPcaySSOXmZRyxxhsbg5272t7h3BS3CTjnw4tWgrFYrxeZ6GsoaGKCXtKOVzOZrQNixrl5V0VpNlBbBfaiaV00rS2JhZytDT9rfc57s42PRS1ktVuq7b21VDnkiDiWD2j7Qb1z5/grf7iw3syoybte/C993I3U6sprLa56+rdMcEeLNO9zaLTV5qHs5nS0jmxVbB4uLC2Qf0l5h4r8AJ7TrustPCyor75LQ0XrtfRyhhfSNcRyRh+wke4ZcGcodgfayoGTTMkNTDWWGump5mM7eKQydk5mHcuQc5ByNsHvC3bhZxtvnDeW50V908LxNXVPrNRUTVDo6p8hAGXSEO524GwwOp3VeGzsRg7yw1TPyi/X0Nat1bpY2XPejzbdpq6e5TvubpjWc5bN2wIe1w2LSO7GMY7sYWI0FxAAJJ6Bdn9IzVWkOIVbFqeyacq7LfOlf7bHxVTANnnGDzjYZxuOvQLF4C6m0noOvZqG76OdqO7NcH0sslcI4qXwc2Ps3Zf+cTttgA7rpRlW6HN0bzfhuvjuIJTi5XcvE9Zeh7Z9bWThDDRazjlgHbufbKef+Ghpi0ENcOrfa5iGncA92wHZ1yfhnx60PrWrithmns10lIbHTV2A2Vx+yyQHlJ6YB5Sc7ArrC+f4+FaNeTrQyt62OlSlFx6ruFrGvLIy4219S2Jr5YmEPaRntI+8Ed/f+K2dU6qpGTi7ot0K0qFRVI8D87OLekzpPVclPCxwt9Tmakce5ud2Z8Wnb3YPetcsdxktd0hrWMEjWHEkZ6SMIw5h8iCR8V6u9JfRAuFhrG00OZ6UGto8DfH22D3jO3k1eQ19L2Ti1jcL1tWtGc3auHWDxKq0dIy60ezs8GSWo6BltuskVO8yUsjWzUzz9uJ4y0+/BwfMFQF3h54RKBuzr7ltb/+stHNf1qLTNyE95gkOR/Vfn/SBQD2h7HNcNiMFXoXnBxe9aeviUMRFQqKcF1Zarx3rwd14Guovp7Sx7mHq04K+VTNwup8KXw6z0hdOFdZIxldNKblpuWR2AK1rcPgyeglYMDu5mjvK5YrtJUT0lVFVUs0kM8LxJFIxxDmOByHAjoQcKKtT6SNlo+HebRdmdP4cT02ptPVfCPU0zaCqNS6fT9VU+yKOv8Aqvp5M7tjlwGn7rwDglX9P1FJdbVJwj4kPNkuNsne2yXSqGPo+cn2qac/yDzg832SQdx0u36ih4v2WXVdhhZHrmhh577a4mgG4saMeuQNHV/TnYO/cDxsUOoNP8TbXT2PXlfHZ9UUsYgt2pJQTHUNGzYa3G+2wEvUfa6b0Xrd2trrbfF81zT8/eSEHRXHXPBzVVdbZqY0VW+MslgnbzxSjfklaQcOA3LXA46jxC0y7XGuu1ymuNyqpaqrndzSSyOyXH/nu9y6vX3nU2h6SDQ/FbSjdRaea3NB28mJImHo+jq259nGDy5LdgMDdZWq+Duly+3y6a4gW+hfcrfT3KC36izTSMhmYHsHbtBic7Bwfq9FLTrQjLNJavitU7fDx97Np1JuCp5uquHI4oi6Y7gVxKeeaitNvuMJ+rLR3ekka73Ykz+CrHwO1tAea+T6c0/D3y3K90zRj3Mc534Kf2qj+Ne8hyS5HMl0fgdwi1DxPvrYqSKSjssDx67cns9iMdS1n35COg7sgnAW/wDBzhhwqreIFr07eNTVWrLhUmQmG3QOgoY+zjc8h8rsPkBDduQN69V6K4ncSdN8KbXDpux2qA3BsANLQwxdnT07CSA52MbZB9kbnG+M5XOx20akJKjRi8zXFW056/MnoUOkd7lOIGpNOcE+GdLYtPQRRVbYDDbKTOTn7U0njuS4n7Tjj3eKLxVz1dXNVVUz5p5nuklkecue4nJJPiTlT2s9Q3bUl5qLveqx9VWTH2nu6AdzWjoGjuAWpVj+qxgMJ0EW5O8nvZfklFWMCrf1UZUO3WXVOyTuo6Z2T1XXgijUZYlKsOVx53Vs9VMiuz5PVUVT1VFk1CIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiA+gvth3VsL6b1QyjLhKz6Z3RRkRWdTlRSRNBk3Rv6bqaon9N1r1I7opqid0VWoi9SZ6X9C/wDv7qL/ACaH+05c/wCKVz4YXDiRqSj1Bpy92mthulRG+4WiqbKJ3CRw53wy7AnqeVw71v8A6Fpze9Rf5LD/AGnLn3FDWWlHcR9SW7UnDm1XD1a6VMTayhqpaKocBI4czy0ua93mWrm4KLeOq2Tei3Oz+KT8SDaDVl8zWjpXhjUe3S8VH0wPSOtsE4c3yJjLwUGlOGcHt1PFb1gDrHR2Coc4+QMhYFUzcFaj230WvaBx6sinpZ2j3FzWlOfgpB7TafX1a4dGPlpIGn3kBxXbzVPxT90focuy5Lz+pt+lrpw6sfDPXtXpyy3O/impKN9S2/FjIKgmrYGARxHPKHEOOXb4A6LQizilxfpmmQQ27S1DuHFrbfZ6BoPXubtk/edut90trHTNv4Za+rtJaEoaF9FR0b3G6VDrgKguq2NHOxwDPZyXDDfrAE5wuG6111q3WUrH6jvlVWxxfwVPkMgi7vYiaAxu3gFz40pyrTajZ33y1a0XBaeZajJKC+XedL1RPZuCcFDRaQMd51TdLbHW/ullYOzpYZgcCkjPRxA/hHe1g7AZ24pUzzVNRLU1Mz5ppXl8kkji5z3E5JJO5JOV0bj5/dWiP+xdq/2RWsaAstHd75Gbs6eO1xHmqHQj23bZDG+Z6eWVPhI/w871k9/N+uRlpynlRriuzU1TDGySanljY/djnsIDvcT1Xpexag0Jp2jaLHoyOGpbsHvDS4++U8zltVm4hWO7RGlusIonvGCJh2kTvecfrHxWlWviYLMqLt3q/uVzrUdl4afVliEpPsdve7HjlStgmqYm1McU8scMrGtlY15DZADkBwGxwRndduOmeHWs7q6KrtrtOVRBcJ6CdrIZSPFrm8rdsnoPerMvBe1z0NS7R+p2XCohf7cU/Lh22wD2/HG2D4qaOLhSmlWTj3rT3q6KstlVqkG6DU12PX3OzOYWiifcbrS0EX16iZsQPhzEDKydU1jK+/1lRDj1cSdnAPCJg5WD+qApWyWy4WK/1/0nSS0tVbaKabkkGMOLeRhB7xzPaQR4LVl1ItTqZluS+PpHNqRdLDqDVm27+Gi83I33gTZBeeINLJKzmgoGmqfkbEtwGf6xafgV7v0fQ+pWKAEYklHav956fhheWvRPsfbUVXXOb7VbWspgcfYYMkj+ufkvXrQGgAYAHQLwn7RYl1MU4cI6Hfow6DZ9OHGbcn8F9SqIi8+QnCvTI1FqC06DpLTZYKttPdJJG19VAxxEcTA38m5wHs85d47hjh0JXi9fqKtH1fwn4e6pY83TTFCJ35JqaVnYS5PeXMxzf0shem2RtylgqSpTh4rj4fqUMThZVJZkz85a0dtX01OfqtzI4e7ovq8zmChcWnDn+yP2/tXVvSJ4XUnDTWVHDbqqpqrfX0hkp31AbztLX4fGSPrYyw5wPrgYXG9RPDp4YS7lAHMTjx//AML2NLEQrUulpu6Zz8jjPK+BDA4Odvkt84Xabferk263ECWipdmMfuHuHQY6co64922FgaGs1Be75HQwsll5GGWaWYBoYwEDDWAnJyQMk436Lt9JTxUtNHT07BHFGMNaBsAtqVO+rLcI31MPUJ/6ux+d+wrXdNTMjtbWyMc5ksZYeV2CPbzkbeQU1qObZsIPQFx/UP2rU9M1HPTvpnHdh5m+4/8Af+tTTWbQkzuFRNG1MkhmY6mgecim7NhkIZzHtQ/HXHTPf3LB1BZ5bm2Ol7E+sx07SOYYc09w38dhjzCtrKtrw2dzO0EZkYWtcTjDuo37twFA4OGqLSqRrWhNb9PD1xOayMLXOje3BBLXArBtX5Pt6U/4GT2f0TuP2rbNc0jYL/Uzx8oimlcRy9Ac/wD+PxXQPRk4R2niPc7xXXmrq4aC39ix0dOQ0zPcHEN5iDgAAZ2z7Q6LGIxVPD0unqaJfM5DoSVR0lvOQDY5Gfgvefow6iv2ouFdLLqOCrbWUczqVlRUxua6qiaGlkmSPa2cWl3eWEndbLpHhvobSYjNi0xbqaaM5bUOi7WYH/GPy/8AFbYvFbY21Sx0FTjDc73e/wB36nQw2FlSd2wiIvOl01riDQipswqQMvpnZ/onY/s+S8B8S7INPa3udtYzlgbN2kA7hG/2mge4HHwK/RusgZU0c1M/6srCw/ELxP6UVpMF4td15MOkifTS4Hew5Gf6zvkvTfs1iHDEOm90l+v1JMXDp9nPnTafhLT46nNNFPbJefo6QgRXKF9G7J+08ewfg8MPwUK9rmPLHtLXNOCCOhX1TTSQVEc8TuWSN4e0+BByFK61hji1RXGJvLFM8VEY8GyNEg/By9stKvevh/s4L6+FT/C/8l8rP3mnXWPkqy4DZ4z+xYik70z2I3+BIUYqtVWmzEHeJnVdyfUWmhtzqSijbRmQiaKBrZpecgntHjd+MeznpkrBRFEkluNzLs1zuFmutPdLVWT0VdTPEkM8Li17HDvBC7NQW7TnGfT151BcJbfo/VNpbC6uuB9i3XAyydm18rQPyMheW8zm+zuSR4cOXSeG/wDEzxU/yO2f79GquKhopx0ldK/e0jeD4PcSEly4ocKKUWHUNqiuOm5zzMornAK22VAO4dE8EgZznLHA77roHFKfhldX6Xdfaa/2Gqm0xbpIHWzs6imhidCC2MskIf7I9nIccgDK4noziNrHSNO+is94k+jpP4W31TG1FJIO8GJ4Ld/EAHzXa+KWptFVD9L/ALp9BsnnqdMW6oFTaq91H2DXwg9myIhzORu4aMbDAyoo0pxxEXl111i7N+D082JyTg/maadI8Npd6fi1DGD0bU2CqY748nMPxVRprhZSflKzidWV7R1it9glDne50rmgfJUzwTk9os4g0uerAaOUD3E8v6lUVXBak/KRWjXFzcP8HU1dNTsPvLGud+Kv5qnOfuj9CvZcl5/U6J6Ot14dx8X7La9K6ZuklVKKjF1u1YDLGBBISGQxgMGcYyS7YlPS4OOKzT/7Oh/tPT0ddYafrOL9ls2ntAWayQTio56l8slXWDlgkd7Mrz7OcAHDRkEhfPpeHHFMH/2dD/aeuHiItbRV011eLu977WvBHVwDWVnEK1/XdQtW/rupOtfuVC1bvNdSCJKrMGpcsGVyyZ3LClO6tRRRmy24q2V9HqvkqQhZRERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAX0CvlVCAvxdVmQHdYUXVZkB3WkiWJKUh3U1RO3Cg6XqFM0R6KtULtJnpz0Kd7zqL/Jof7TlwbjR/G7q7/PNV/tXLvHoTnN51H/AJLD/acuD8aP43dXf55qv9q5U9lf1Ct3L5FbaW5GooiL0xyToXDykkruFXEulifGx76GgwXnDdq2M7n4Lng0nUj69xt4/wDeH/gujcNf4ruJX+Q0P++RrRFTo0ozq1W+a/xiWoytCPrizsmteGtDqaXSVVcNVUVvgo9JWyKePGZCBEcOBJAwd/l0Wo3CDT1hlFutV2p6ynjH12MLd+/Oep81l8a3ObUaQAcQDpG25APX8mVz5RbPw0owU3PR8LL/AGW6uJp5FCNNJ8Xd/wCjfNMmjvepLXZY6wRvuFZFSteGF3KZHhgOO/GfFYkdXTSVDqdkwdI0kEYI6deq+uBtOarjBpSMNzi6QyY/QdzfsUDqeJ9v1ddYBlj6evmZjwLZCP2K2pfxnT7E/NkPSvLc2NZlnuldaK1tZb6h0MrdsgZBHgQdiFG01TFNStqOcNaRvk9D3hRd5usRhdT0z+ZztnPHQDyWzgprK1dEyq9G1OLszolRrakvzX0mpbVQ3CmkZ2T3U7jHMG8wdgODumWg426BQd64d2y7Wua5aEmraiSnOZ6CqLe1LfGPHXHgevcc7LUdP6duN5imqYAyCip8dvVzEiOMnoMgElx22AJ3UvZm3KyXdtTbrnJ2bOj92O+AyRj47jqqfssabaw8srXDh4r6alp4qWISeKhmT47peD4+aPSHot2p1HpqyxSxOjlayaeVrm4IcXuxkHwBHyXfF460vxou2lqrtqttNWzO2JeOQlp6ghox3DfAO3VeiOHfFbSmsbe2SOtht1aAO0pamZrT72OOA8de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h8me9W3v81aLsqRIhci456tlx8V8kqhW1jS5XKpnzVCqLJgrlMqiICuUyqIgK5VERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAVQqIgPoL6BXwECC5ea7zV1knmsYHC+gVq0bJmayXzWRFMo1r8d6usk81q4kikTEU6zYajzUDHKQsqKY+KjlAmjUNjp6nzWx6W1HdrBco7jZbjUUNUzpJC7GR4EdCPI7LRoJ91I01R5qvUppqzLVOqetNAcfbPfKL6C4i2+maydvZvqhD2lPKPCSMg494yPJoU9e+Cun9RcSLTxIs16M8ZrIqypgdIJoakMwQY3g7fVbscg79F5BpqjOy3bh9xA1NoqsE1kuLm07nAy0kvtwye9vcfMYPmuRPBTotyw0sraatw1Np0YVUZtPSaj0yOKWrdTW2qt95jtz4WNmbgiaunEZkY7o7DTJhwOOq8+L336a/O/gJXOj3b65TF36PP8A8SF4EXR2bini4SrNWd7e5I5dSn0byo9JaeHZ6fsvUdnoKtk6eLol0vhe3l4baaH/ALKpj08Y2lc0oh2enKU4xycNpnf1gw/sXUeHbeTh/pxv3bVSj/4TVw8X9jx+p9B2b/M/7fp9CSvNvobpbJqG40sVVSyj24pG5a7ByMjyIHyWWAAA1oAA6DCpJ/BO9xVVz7u1jsqKvc0bi9sdHu+7qmi7vHnH7VybV7P/AAG4nMx9TU4f85Aus8YtqPTD/uamoHf65XLNXs/8FOLjMfUvVM/5zNXXwP2I96/yR5vaq/iT7n/hL6HEqCrqKCup62kldFUU8rZYntO7XtOQR7iAu88RND37WvFyom0jZpaqO901Ldw5g5YohURNkc57z7IHOX9Tv3brz+v0Z0ZdqjTfoy2W+QxxOqaTTFPPG2QHlc4U7eTmxuR9XvXUx+Mng5RqU1du699voeKp0VW6rNF0FwD0XoS3DUfEa5UdwnhAcWTO5KOJ3hg7ynwyMH7qweJXpDFkLrVoKlbTQMbyCvmiAIA2HZRnYDpgu/qhcW1rrDUGrbga/UFylq3jPZxk4jiHgxg2Hd+1apVVHmqawk68+kxUsz5cF4HTp0YUVojNvd4rbnXTV1xrJquplOZJpnl73HzJUJUVPmrVTUeajp5/NdSFNI0nUL81R5rDlnWPLNv1WM+UqdQK0qhekmWO+Uq2+TzVlzz4qRRIHIuPk81bc8lfBcvknK3saXKlyoVQqiyalSVREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAVCBURAfYK+g7CtgqoQzcvteR3q9HJhYfMrjHrVo2TJOGXBWfTzkHqoSN6zIJcd6jlEmhM2Gmn6bqWpJwRutYppum6laSboq04l2nUPbmu6Q8RfRbq2UoM1RVWSOoY1u5dPDyyFg8y+Mt+K/PRe4vQ31nHWWWs0XVzfl6RxqqME/WicfbaP0XHm/pnwXnL0nuHE3DziRVNpoC2yXRzqq3Pa32WtJy+L3sJx+iWnvXK2VPoK9TDS53XruKuLhrmRvc9RRQ0NJbKm4UNFNW8PI6SmNXUNia+R4LQ3LiB3LYtN63rbBp630uotK3CnoaWmjg+kqCVldT4Y0N53GM5YNvArz/TcRLwaemprvbbHfYaWFsEAuNuje6ONuwaHtDXYHvUvaNcaPiqO2OlrnYKk/WqrDdXxn4Rvy38VJUwMmrSjfu/2vgzu0drQUs0JZe//T+MT1Tabrbb1a23C010NZSyNPLLE7I9x8CO8HdYWq9V2LTEEcl3rmxSS7Q07Gl80x8GMbuf1brz3adV0FBdHXXS2tIKSqmBE9NeLa6BtQMbdo6DMZcOodhrvElYzNSWajrJ7ld9dV9bc6j+6JrJQ8szvIVE+Cxo6crGtbt0VJbM62t7dzv8PM6ktuLJpbNzurfHy4HTNaX686kitTX6ZfYrXBc6esdW3iuhpn8sb8n8kTzdM960++VNJcdPcYJqGphqaZ9VRSxywvDmPHaZyCNj0WmVmstHRTOmodDG41R61d6uMlQ5/vYMN/FRN217eq211VppaW0Wm3VYaKimt1BHC2XlORzHBccHzXRo4OUbJK274p83y7DjYjaVOTblK7ae7ti4rhHTXtNfs1uqrvd6O1UMZkqq2dlPAwfae9wa0fMhfoD6QM1NpTgI+ywPwHR01sp+7Ibyk/6kblwL0IeG8t61c/Xlypz9G2dxZR87dpqojqPEMac/pFvgVsPpg60juurKbTFFKH09oaXVBadjUPAyP6LcD3lwVXHS9pxsKMd0NX69bzlYSFlmZw2rn64UVUz+a+qufqouplyuxCBNUqFJ5iT1WDNLkpNLlYkjzvurEYlOcz6fJ5qy55K+HOXwSpEiFs+i7K+cqhVCtjW4KFURDAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAVC+gcL4VQgLzHYWRE/Cw2lXmO81q0bpknBIpGmm81CRP36rNglx3qGUSxCRu+itSXHTOoaK+2qfsqukkD2HucOhaR3tIyD5Er2ZPFoz0g+FLqeccjnYLgCDPbqkDYjx7/JzSfh4Mpp/Nblw71vfdE32O72KrMMo9mWNwzHMzvY9vePxHUEFcnH4J1rTpu01uZaTUlZkFxY4aan4bX51uv1I40z3H1SujaTBUt8Wnud4tO492CtLX6C6L4scPOKNkNg1NTUVLVVDQya3XENdDKfGN7tj5dHZ6eK0zXvokaYuU0lXpC+VVje48wpahnrMHuaSQ9o95ctKG2FB9Hio5Zc+DKk8M19k8WovQFx9EviXTyltLX6drGdzmVUjD8Q6MfrV+z+iPxCqZR9I3fT9BDn2iJpJX/ABgB/rK9+88Ja/SIh6GfI88LqvAbgpqDibc46l8ctu05E/983Bzcc+OrIgfrO8+je/uB9IaA9FvQOmC25aorZtRTwjncKkCCkbjfJjBJOPznFvkszihx90xpSgdZNER0tyrYmdlG+FoFHTAbDGNn42wG+z59y59ba0qz6PCRu+fBeu0np4Z3vImeKWstPcF+HtLp3TcEENf6v2Nso279kN8zSeO+Tvu52fziPFF0rpqqplqaiZ800ry+R7zlz3E5JJ8ScrK1Pf7nfrvUXa71stZW1DuaSWQ7nwA7gBsABsMDC16omyeqsYDBLDxd3eT3stSkoqyPmplyo+eTzX1PJusOV+e9dSKKk5HzK/zWO9xKq9ytlTJFdsoVQlCqLJqEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAERVwgKIq4Pgm/n8kBRFXDvBV5XfdcgPlF9cjvun5JyP+6fkgPlF99m/wC475KvZyfcd8kM2LaK52Un8m75KvYy/wAm/wCSCzLSK72Ev8m75J2E38k75JdCzLSK76vP/JP+Serz/wAi/wCSXQsz4C+2lfQpqj+Rf8l9CmqP5F/yWLoykz6Y7zWRE/zVhtNUfyL/AJK6ynqf5F/yWjsbq5nQy471mwz+ajI4KkY/Iv8AksiOKp/kX/JRtInjJkvFUY71u+kuKmutMRshs2pq2KnZs2CVwmiaPAMeCB8AucsjqR/gX/JX2Mqf5F/yUFSlCatJJk0Zs73R+kzxDhjDZY7LUn70tI4H/VeArVx9JbiNUsLYZLTRE9HQUmSP65cFwwNqcfwL/khbU/yL/kqv7uw175Eb5uw27V3EDVuqSRf9QV1dHnPZOkxED4iNuGj5LVJajPerD2VX8i/5Kw+OpP8AgX/JW4UoQVoqyNHNn1NPnvWFNLnvX3JDU/yL/ksZ8FSc/kH/ACU0UiCTbLUsmSsd7lffTVP8i/5Ky6mqevYv+SlViF3LDivgq+aWo/kX/JUNNUfyL/ktrojsywiu+rz/AMi/5J6vP/JP+SzdCzLSK72E38k75J2Ev8m75JdCzLSK72Mv8m/5KnZSfyb/AJILMtornZv+475KnZv+475ILHwi++R/3HfJU5HfdPyQwfKL65XfdKph3ggKIq7+fyTB8EBRFXCogCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgKhBy9+VREB9gs7wV9AxdSCrSLFjNy+DB3gr7DqbvBWKiWM5jOa6k8F9h9F4KORYymc/YSrX0HgFdbJbu/HyUKixkM9J2E+2S29/KrjJLX+atcRY6PtNlW7DaWSWrwarrJbT4NWoquVjou02VfsNyZLZ/Biusmsv5i0jKZPiVr0PabLEvkjfWz2PwYrrJ7EPuLnuT4pzO8Vh4ftNli3+FHSGz2HvEf4K6yosHeI/wAFzPmd94pzu+8Vr7N2myxv5UdSbUae/m/wV1tTp3G4j/Bcp53/AHk7R/3isey9pssd+VHW21Om8f4P8FdbU6Z7xH+C4/2kn3inayffKx7H+YytoW+6jsranTHhH+CuNqtL+Ef4Li4ml++5V7eX75Wvsf5mbfvL8iO2NqtK+Ef4K4yq0p4R/guH9vL99yr6xN99yx7F+Zm37z/IjubavSf83+CvNrNJeEf4Lg/rM/8AKOQVU/8AKuWPYfzM2W1PyI762s0h4R/grrK3SHhH+C8/iqnH+FcvoVc46SuWPYPzM2W1fyI9BtrtIfzfzCuCv0h4M+BC89itqP5V3zVRW1H8q75rX2D8zM/vX8iPQwr9IY6M+YVDX6Q8GfMLz567UfyrvmnrtR/Ku+aewfmZn96/kR6BNdo/wZ+CtvrtIfzfzC4B65P/ACrl8msqP5VyewfmZj96/kR3x9bpDfaP5hWX1ukPCP8ABcHNXP3yuXyaqc/4Vy2WA/MzH71/Ijur6vSJ7o/wVp1XpLwj/BcNNTOf8K5PWZ/5Ryz7D+Zmv70/IjtzqrSfhH+CtuqtKY27P8FxT1ib77lTt5f5QrPsX5ma/vP8iO0OqtL9wj/BWn1OmO7s/wAFxzt5fvlUM0v33LPsf5ma/vL8iOvuqdNdwj/BW31Gm+4R/guR9rJ98p2kn3itvZPzGv7w/Kjqz6jTvhH+CtPqNO/zf4Ll3aP+8VTnf94rPsv5jDx35UdNfUaf32j/AAVl89h/m/wXOOd33inM77xWfZu019t/KjoL57F+Z+CtOmsfgxaFzO8UyfFbLD9pq8W/wo3h81l7uRWXzWfuDVpuT4lMrPQ9pr7S+SNtfLaM9Gq0+S0+DVq+VRbdF2mvT9hsj5bX3BqtOfbO7lUAiyqfaa9N2E06S3HwVpzrf4BRSLKh2mvSdhJF1F3AK2XUf3Vgos5TGfsMsml7grZMHcCrCLNjGYukxdwK+SWdwK+ESxi5U8vdlCqIsmAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAq5VEQFcquVveiuHk13oRd7xV/Rts5ecOOOd7e9wzs0eZ+WN1kVeo9I2Jxg0xpynrJWbeu14MmSO8NP/APz7lA66zZYK7NsvFmj0NuuNc7FFQ1VUc/4GFz/1BTMGh9XTDmbYK1gP8q0R/wBrCnq2+65uUMQddvVYZ4TNHHTjkDYxjJywZAGR1KiZLVfrg0Plub61pGx7aSXI8sha9LLml5/QkVGXBMoOHusCM/RcY/SrYB+t6Hh7rADa1Ru/RrIT+p6+otHXKRpdiRoHUuYGgfNwP4Kk+j7lDsWyk525Yg4H+q4rXpn+Je79Tf2ep+FmNUaI1bC3mdYK148Ymdp/ZyoWuoa6hdy1tHU0zvCaJzD+IWxMtt+tzcxXZ1GOn8O+P3dFL0eoNb29tTEbo2rjomB9RBUt58NIyM84BOfIrbpZdj8vqaOjJb0c9z5qmV0SjvujNQOFPqOwQW2d+wrKD8m3PiWjp8Q5YWudAVVipjc6CoFwthAPaNHtxg9CQNiPzh8gtlXWbLJWZHl4o0jKoiKc1CIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIsmkoa2sdy0lHUVB8I4y79QUrFpG/OaHy0QpWfeqJWxAf1jlauUVvZmxAotkbpukh3r9RW2Lyg553f6ox+KyILZphp5RLebk8fyMLYmn58xWM64BK5qaqBkrdA62Ur2Cn0pExzjhsldO94J8xlrVmzXC90bD6oLdbz92lpWsH9ct/asZ3y8/9m6pTabSNQorDeq3HqlprZQftNhdy/PGFJN0Zd2f3dJb7cP/AFqrY0/IEn8FJvqaqvpyai7V1VPjeB8/IPhnIPwUbb5qCPnhrKYiTO0u7uX3t6FLzfr18DborNZna/r15n23Ttkg/u3U8LnDqykpXyZ9zjyhSktp0hbXUs80F1uNLPgicStZH+cMNGeYd7SQoKWmnnne6mjdUMz9eGEhvyxssmi+kKIOaJqeOJ/8JHLIxzXe9mSfwysuF/vEDk07G6ah1FLX2uosMzKejtlTCGUVZC5zoyWkFoce4EDBGMjO65lX0NVQTdlVQujcd2k7tePFpGxHmFskVVQQB3ZVTqYv+uynYZYX++OXH4krNpX00wEFDD603OXxxy8jHHxMcjS35FRxp9Guqja7e8+bLc6E01pZJVwxuZR1EEvO4DlyRy5z44Wx6UroW6ZoTLNGzlhDTzOA6bLVK+zQOeee0VFMepcyF7R8wXj5NUZNaLeDyisfCfB2/wDaDFFLDqaLtLGyg729afQ3266ps1LC9prWTPLSA2H2z8xt+KuUGprPWNBir4mOP2ZDyH8f2LnRs1P3V4/+F/8AyJ9D0/fXgfCI/wD+xa+yQtvJP3lUveyN81hVwPs8be2jLH1MQc7mGMcwJOfgtbudzpHO1M9tTG59T2TIQ12ecDY4woyG00Bdj1t8x8Ggj+y16lKCzRMkHZ2aeoI3DpIXuHzc5jfm1bwoKC9dhFVxjqO9vVmvmavbqCqr5SymiLg3d7ycMjHi5x2A9630a0bbrVHp+KmhuVBHTeryveXNMpIIdg9zd8DbOyibpFCfyNdJNQsbuyHtA9o9zGMDR81FMio2yh8VW1zWnpUQuaD8Gl361P0caivJFK7W4zfVNKVcbpvo69ULW9XQyNmjb7+YA/isd2nrLP8A3FqeEOPRtXTPj+bhzBZra6sfLFmKhmp2dIoXMGfcHb/grNVMe1LH0DrfTSOzI8wkuI8iRt8FqlK/63/UncadtJeXpWMR2jbu7Jon0FwH/qtWxx+RIP4KNrbFeaLPrVqrIgPtOhdy/PGFOVklkcAGhwDdmCAEOP6RcFn0Rr4AJKa5VtKwj2IoZnSb+ZHshM8krv4evgbeztu0Wn3M0IjBwUW91t3ucTHC6yWyseOkVTTMkcfeQP2rGldbJab1mu0vBEw/bp6l0Ofc0k5+S2zS5ef1sQunJO1jTUW0G36XqQTFUXajPeXxMmYPkQVadpyml3odQ26QeE/NC7/WGPxWc64o1sa4inZdJ31rS+KjFSz71PK2Qf6pyouqoaykdiqpKiA/zkZb+sLZSi9zFjGREWTAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAF9NBc4BoJJ6Ad623S+lIqqi+lLtMYaMNL2sacFzR3k9wWZDfaOJz4bDT0Vsp2bOqpWh0rvcDue/qoXVV7RVzZQbNZpNO3yqAdDa6otO4c5nIPm7AWWdJXWNvNVSUNL/jqpg/UStjjmoqtxNXcqmscdz2z3MZ/VGGr7iqrDAcRvoYyPANBUTrz4LyLMcKmruSNYbponY36yDy9aJ/U1Haax/wDf9jP/AOpI/W1bfFdre94ZFVxOd3NYcn5BZTJ2yNyCcHxGP1rV15reSLBxe6Xr3mjt0pcZRmlqLdVeUVU0/rwvk6S1DnH0c739qzHzzhbrLBSTDEtNBJ+kwFYstspeTlgfNTjwjkPL8WnI/BFiZGJYJrczWjpKsgjEtwrqCjYfvylx+AaCr79P2eli7aoudXWRj6xo6cco97icfgr9dDLbD2smTA44dPS/k3t8OZn1SPl71RkLu2jkyIRI3mhr6YcjCPzxsB54wRv1Uyk5a3Kk4yg7NGKyXTcBxDZqiqPc6pqiPmGAfrUhFWVkTo/VLTaqJjuk8dMJMDzceZY76JtRUOoq801NXZ5Y5GHaQnoHBuwzt7W3XfKwmPbQvki9bqGuBLXsZGMZ6Ebn9i3yxlu+bMQaT65LzV13kkLbheattOdmvgdiM+RLdh8lHzwUna8tTJLG927JTKJWO9+ACrZfLOzLaOqmZ/OyOLP9UNwvkGSPp6hA33NeR/acsxi12EjqQ3KPvMumnpe1dGII3SNPsiCEPY73kguX1IKhrswU8kTS7L4piIonf0S73d6xxdIaaEiqE9xyejKl0bWj3cu/evmSaklp/XKWGUszh0bpiezPgdskHffKxls9TbpZyjpwM58r3NLHuoo2d8YD3ge4D2VagxGOzZWVsjc7MZiPHu+so71+Rv8ABRQx/wBEv/tEr5dcK1wx61K0fda7lHyGykVMjdaTd2yXfTOecyUbneD6qV2fmSB+Cp2b2dKympz/ADTBn+sxv7VB9rJnd78/pL6bMcjmdLjvw5bZDTMmSk0VPKeaetq6gjxH7ST+pfHZ0jf4Om5v8c8n+zyrFYJi72WVGO7LcrPqaSopzG17HO52NePZ8R0S6WjZlJMtc8o2i9Xj8OWFuR8Tk/itw4f358bxbK+Rr3OP5CV31s/dJ/V8vBaaTyAh7HAnp3IXcj/ZdnHQjKWQsds7f/nKxZ5Yy7AY3bqcLXNLXz6Ro+ymcPWYhh+T9Ydzv+KkO178n5qni5NRyriZgtSRi7Jz8vYw+RCpJ2THnkYz5LCidzbnp71SR/KfJVckui3G19SRgmYDgsbk9DhZHbqEE2/X8VH6qvn0fR9lA4esyjDfzR3u/wCCtYSTlGz4Gs1qRfETUvNL9F0Dg1zD+Xmb1z90H9fy8Vpnr0p/hI4JB380Tcn4gZ/FXXkuJPOcnqrZZzfbPyH/AAV1JGrRTt6V/wBejDf8VKR/a5l9wzU8Z5oKurp3HuDc4+II/UrRgaT9Y/JfPq4+/wDgs2RizMwyzP2FXR1J/nWDPze0frVBFId/o0OHe+me4/iC4fgsQUziQGuyT0GFQ072nZwBC1yoWZlRVEUR5WS1UGDnlc1su/xwvqeX1qdkstVTTOb9l7XMLvI7Y/FWRLWgAesuc0fZe4uHyOyrzPP8JBSyf0eT+zhYy63Ns07WvoZz6ieRzS2mlLWdIqWoaW/JoyviWop6iXtLi0skb9WEsLR8XYJKxXeo00QqammcRnDYmy4Eh+WQBtvlXGXGlniAp2T0DQejqh0jXfABRZVeyRM61Rfa1ufZbQ+stfBI4yP+rHC7kDP6RUgyqutEzH01VD8xx5mAe95AKjiwzM5oxRTDzDWZ/suXy6nZyflaKohH5jzy/iD+tZcb72Y6SLveJmmumqQXz2611kf2ppaYRH+sCPwWNLHYpAO1s8kGTjmpK0PyfIOyrMkHrTmRirnc7YMa9mR8wf2K62lr6eR1HRmldMCWudE72/MZdjz6LGRL1Y1vFvj69cyzLabG8+xc6ykP3amlz+LT+xWXaclfvSXO21Pg0T8jj8HAL7gpq54kMs0kNO1vNLK5xLMfDqTtssdtQx0ohttIJHno+YBzne5v1R+PvR6cSPfuPsaWvxOBb3e/tGY+ecL6dpe4RD981FBTf42paP1ZVuanvk7S2SOqcwfYyQ34DosX6MuH/wCCn/qFYzS5o2yPkZo0+O++WUf/AKk//Sh094XyzO91SR+tqxG2y4ux+85vi3CPtVxbjNHL07hn9SXf4hklyMxulrnIOamfR1P+KqWH9ZCxaqw3mmHNNbajlHVzWcw+YyFiz088BxPDJGe7maQsmjutzpCDTVs7A3oOclvyOyz1+DMWtvI9wLSQ4EEdRhfK2ul1JT1pEF/oIKlhGO3azD2+e37ML51JpqOmpPpG2SmalxzFpOS1p7we8IqlnaSsYsasiIpDAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAEREAREQBERAdH0tWMvWmn2yVrmGKEQucO8Y2I88DooOgLLfWyWKuhjqBz+y4NyMkd+URU7WlJFik7SRIOsltdjMUhA6NMjsD8Vg3G12ijHaSx1Jad8Mfn9aItIzlzLs6cFG9iMfU2QD8nbZX+b5i39RX1SXeCmJMdva7fLS+UuI/BEVpQTWpRc2np8DI/dNOMllHTtz71VuqasH2qeE+4kIidFDkY6epzLc15rbri3iOCMTODc7+P/AD3LIMAqZ6azROLY6QP5pHdXH6ziB8NkRElF6Gk5OWrKwytuN7fWOBZDTtEhb9osYBge84H4rCqblUzVMswf2Re8uPZgNO5z1HX3oilglfwNGWm1dS0l3bPPeeY5/Wvo11Qe+I++Jv8AwRFJlXIZmtzLkNTI92HNicO8dmBkfBSFNZGt5pqWrfEyVv1THn2T3dURVq8nDcWsPFTvmKVVFNQwtlL4KlnMGkSMLSPDGDv8VaNRDn+4Yh/TcURbUevG7MVepNpB1RFj2aGmJ/OB/wCKs+tioY4CipGbdQwgj8URSKC3kOd7jF9XP3h8lSqdI4sMj+YtYGjyAGwRFJxNGrFvtJB9t3zUvbLPXV0QljqIms/OJz+pEUdRtK6ESXstoqaauZPFX+3Gd29ns4dCM5W1vf39x6hEVOUnOLuTSilax8dq9jsAqvaPe7BKIq635eAKtk3zvt0WrXi21FRVSVMtUHOedhy9B3BEU+dwSym1KKk3ciKmhlp2c7nsLfLqsTJRFdg7q7NZpJ2QyVTKItjQZVeYYI35vFEQDKzbVZ6q5Qvl9bZCxruUAMJJ/FEUVeTjG6Ber9NCJnrVZXOlbGAOVse+B3ddlEubGTtG0DuCItKE3K9zLWh8lhb/AAbi0+HcVWnqHh2xLXDvaURWDQzIK6eKeORzu0LHBw5xzdPM9FkSyGhuzKpoD4ZgX8vR3K4bj37oiiklczwLEjOynntExBZVBvI9o3BzlpI/WoUF9ur3BzI5JIX43Jxkd/ciLG/3GL2ZMHU5wP3nv/jP+5U/dM/P9xjGP5T/ALkRadFDkTPEVOZT9079/wB6D/Sf9yo7U03dSs/rlEWeihyDr1OZan1DNNGWGlgIPc8FwUZLVSulMjMQc32YvZb8giLMYpbiOVSUnqy5QU8tyrIqYPAe8n23klbdqKrZadPNt0TXPMkRiDj0AxuffuiKOprOKC3M0FERWDQIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgCIiAIiIAiIgP/9k=",\n      "sizes": "192x192",\n      "type": "image/png"\n    }\n  ]\n}');
    return;
  }
  // Service Worker
  if (pathname === '/sw.js') {
    res.writeHead(200, {'Content-Type':'application/javascript','Access-Control-Allow-Origin':'*'});
    res.end("const CACHE = 'erdem-bi-v1';\nself.addEventListener('install', e => {\n  e.waitUntil(caches.open(CACHE).then(c => c.addAll(['/'])));\n  self.skipWaiting();\n});\nself.addEventListener('activate', e => {\n  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));\n  self.clients.claim();\n});\nself.addEventListener('fetch', e => {\n  if(e.request.url.includes('/api/')) return;\n  e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)));\n});\n");
    return;
  }
  // ── Ana sayfa — config'den HTML dosyası serve et ─
  if (pathname === '/' || pathname === '/index.html') {
    const htmlFile = CONFIG.server.htmlFile || 'ERPBI_v9.html';
    const htmlPath = path.join(__dirname, htmlFile);
    fs.readFile(htmlPath, (e, data) => {
      if (e) { res.writeHead(404); res.end('HTML bulunamadı: ' + htmlFile); return; }
      res.writeHead(200, {'Content-Type':'text/html; charset=utf-8','Access-Control-Allow-Origin':'*'});
      res.end(data);
    });
    return;
  }

  // ── Genel statik HTML dosyaları (.html uzantılı) ─
  if (pathname.endsWith('.html') && !pathname.startsWith('/api/')) {
    const safeName = path.basename(pathname);
    const htmlPath = path.join(__dirname, safeName);
    fs.readFile(htmlPath, (e, data) => {
      if (e) { res.writeHead(404, HEADERS); res.end(JSON.stringify({error: safeName + ' bulunamadi'})); return; }
      res.writeHead(200, {'Content-Type':'text/html; charset=utf-8','Access-Control-Allow-Origin':'*'});
      res.end(data);
    });
    return;
  }

  // AI Değerlendirme endpoint - POST
  if (pathname === '/api/degerlendirme' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', async () => {
      try {
        const data = JSON.parse(body || '{}');
        const sayfa = data.sayfa || 'genel';
        const veriler = data.veriler || {};
        const sirket = data.sirket || 'HOLDİNG';

        const veriMetni = Object.entries(veriler)
          .filter(([k,v]) => v !== null && v !== undefined && v !== '—' && v !== '')
          .map(([k,v]) => `${k}: ${v}`)
          .join('\n');

        const prompt = `Sen deneyimli bir CFO ve yönetim danışmanısın. Erdem Holding bünyesindeki ${sirket} şirketinin ${sayfa} raporunu patron gözüyle değerlendiriyorsun.

Finansal veriler:
${veriMetni}

Görev:
1. Patron/CEO perspektifinden kısa değerlendirme (3-4 cümle)
2. En kritik 2-3 risk veya fırsat
3. Acil 1-2 aksiyon önerisi
Türkçe, net, doğrudan. Jargon yok.

Format:
📊 DEĞERLENDİRME
[metin]

⚠️ KRİTİK
• [madde]

✅ AKSİYON
• [madde]`;

        const apiKey = process.env.ANTHROPIC_API_KEY || '';
        if (!apiKey) throw new Error('ANTHROPIC_API_KEY tanımlı değil');

        const resp = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01'
          },
          body: JSON.stringify({
            model: 'claude-opus-4-6',
            max_tokens: 500,
            messages: [{ role: 'user', content: prompt }]
          })
        });

        if (!resp.ok) throw new Error('API hata: ' + resp.status);
        const result = await resp.json();
        const yorum = result.content?.[0]?.text || 'Değerlendirme alınamadı.';

        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ yorum, sayfa, sirket }));
      } catch(e) {
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ hata: e.message }));
      }
    });
    return;
  }

  if (handler) {
    try {
      handler(req, res, filters);
    } catch(e) {
      err(res, e);
    }
  } else {
    notFound(res);
  }
});

const PORT = CONFIG.server.port || 3000;

// ════════════════════════════════════════════════════════════════
// D1 TUNNEL POLLING — Velox Pulse Tunnel (Cloudflare D1 ↔ AX SQL)
// ════════════════════════════════════════════════════════════════
const https = require('https');

const D1_CFG = (CONFIG && CONFIG.d1) || {
  account_id: '7fde81b1c4e38af35824fe944271fec4',
  database_id: 'b0c43319-5849-4d6a-9659-08cb52ae2f88',
  cf_token: 'CHANGE_ME',
  table: 'VLX_TUNNEL_JOBS',
  poll_ms: 1000,
  heartbeat_ms: 10000,
  max_parallel: 4,
  sql_timeout_ms: 300000,
  // MULTI-TENANT — config.d1.tunnels[] varsa onu kullanir, yoksa tek tunnel'a duser
  tunnels: [
    { name: 'KK',   tenant_recid: 1, tunnel_recid: 1, dataareaid: 'kk' },
    { name: 'NT',   tenant_recid: 2, tunnel_recid: 2, dataareaid: 'nt' },
    { name: 'YTY',  tenant_recid: 3, tunnel_recid: 3, dataareaid: 'yty' },
    { name: 'ELM',  tenant_recid: 4, tunnel_recid: 4, dataareaid: 'elm' },
    { name: 'NFGE', tenant_recid: 5, tunnel_recid: 5, dataareaid: 'nfge' }
  ]
};

// Normalize tunnels (eski single-tenant config'i de destekle)
const TUNNELS = (D1_CFG.tunnels && D1_CFG.tunnels.length)
  ? D1_CFG.tunnels
  : [{ name: 'default', tenant_recid: D1_CFG.tenant_recid || 1, tunnel_recid: D1_CFG.tunnel_recid || 1 }];

const d1Agent = new https.Agent({ keepAlive: true, maxSockets: 8 });

function d1Query(sqlText, params) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ sql: sqlText, params: params || [] });
    const req = https.request({
      hostname: 'api.cloudflare.com',
      port: 443,
      path: '/client/v4/accounts/' + D1_CFG.account_id + '/d1/database/' + D1_CFG.database_id + '/query',
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + D1_CFG.cf_token,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      },
      agent: d1Agent,
      timeout: 30000
    }, res => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', c => buf += c);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            const j = JSON.parse(buf);
            resolve((j.result && j.result[0] && j.result[0].results) || []);
          } catch (e) { reject(e); }
        } else {
          reject(new Error('D1 HTTP ' + res.statusCode + ': ' + buf.slice(0, 200)));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(new Error('D1 timeout')); });
    req.write(body);
    req.end();
  });
}

const activeJobs = new Set();


async function pollAndExecuteJobs(tunnel) {
  if (activeJobs.size >= D1_CFG.max_parallel) return;
  let queued;
  try {
    queued = await d1Query(
      'SELECT RECID AS JOB_ID, JOB_TYPE AS TYPE, PAYLOAD, PRIORITY, RETRY_COUNT, MAX_RETRIES ' +
      'FROM ' + D1_CFG.table + ' ' +
      'WHERE STATUS = ? AND TENANT_RECID = ? AND TUNNEL_RECID = ? ' +
      'ORDER BY PRIORITY DESC, CREATEDDATETIME ASC LIMIT ?',
      ['queued', tunnel.tenant_recid, tunnel.tunnel_recid, D1_CFG.max_parallel - activeJobs.size]
    );
  } catch (e) {
    console.log(new Date().toISOString() + ' [WARN] poll t' + tunnel.tenant_recid + ' failed: ' + e.message);
    return;
  }
  if (!queued || !queued.length) return;
  for (const job of queued) {
    if (activeJobs.has(job.JOB_ID)) continue;
    activeJobs.add(job.JOB_ID);
    processJob(job, tunnel).finally(() => activeJobs.delete(job.JOB_ID));
  }
}

async function claimJob(jobId) {
  try {
    const r = await d1Query(
      'UPDATE ' + D1_CFG.table + ' SET STATUS = ?, STARTED_AT = strftime("%s", "now") ' +
      'WHERE RECID = ? AND STATUS = ?',
      ['running', jobId, 'queued']
    );
    return true;
  } catch (e) { return false; }
}

/* msnodesqlv8 hatalari bazen array of {message} olur, bazen string. Tek string'e indir */
function extractErrMsg(e) {
  if (!e) return 'Unknown error';
  if (Array.isArray(e)) {
    const m = e.map(x => (x && x.message) ? x.message : String(x)).filter(Boolean).join(' | ');
    return m || 'SQL error (no message)';
  }
  if (typeof e === 'string') return e;
  if (e.message) return e.message;
  try { return JSON.stringify(e).slice(0, 500); } catch (_) { return String(e); }
}

async function postJobResult(jobId, status, result, errorMsg, durMs) {
  try {
    const rowsRet = (result && Array.isArray(result.rows)) ? result.rows.length : null;
    const resultJson = result ? JSON.stringify(result) : null;
    const bytes = resultJson ? Buffer.byteLength(resultJson, 'utf8') : 0;
    await d1Query(
      'UPDATE ' + D1_CFG.table + ' SET STATUS = ?, COMPLETED_AT = strftime("%s","now") * 1000, ' +
      'RESULT = ?, ERROR_MSG = ?, DURATION_MS = ?, ROWS_RETURNED = ?, BYTES_TRANSFERRED = ? ' +
      'WHERE RECID = ?',
      [status, resultJson, errorMsg || null, durMs, rowsRet, bytes, jobId]
    );
  } catch (e) {
    console.log(new Date().toISOString() + ' [WARN] result post failed: ' + extractErrMsg(e));
  }
}

// ── Güvenlik: file_write yalnizca bu kok dizinler altina izinli ──
const DEPLOY_ROOTS = [
  'C:\\TEMP\\public\\',
  'C:\\TEMP\\',
  '\\\\192.168.41.90\\C$\\TEMP\\public\\',
  '\\\\192.168.41.90\\C$\\TEMP\\'
];
function pathGuvenli(p) {
  try {
    // UNC yollarda path.resolve guvenilmez; normalize edip prefix karsilastir
    const norm = String(p).replace(/\//g, '\\').toLowerCase();
    return DEPLOY_ROOTS.some(r => norm.indexOf(String(r).replace(/\//g, '\\').toLowerCase()) === 0);
  } catch (_) { return false; }
}

async function execFileWrite(payload) {
  const target = payload.path || payload.file;
  if (!target) throw new Error('file_write: path yok');
  if (!pathGuvenli(target)) throw new Error('file_write: izinsiz yol (' + target + ') — sadece C:\\TEMP\\ altina yazilir');
  let content = payload.content;
  if (content == null) throw new Error('file_write: content yok');
  if (payload.encoding === 'base64') content = Buffer.from(content, 'base64');
  // yedek al (varsa)
  try { if (fs.existsSync(target)) fs.copyFileSync(target, target + '.bak'); } catch (_) {}
  const dir = path.dirname(target);
  try { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); } catch (_) {}
  fs.writeFileSync(target, content, payload.encoding === 'base64' ? undefined : 'utf8');
  const size = fs.statSync(target).size;
  return { ok: true, path: target, bytes: size };
}

function execFileRead(payload) {
  const target = payload.path || payload.file;
  if (!target) throw new Error('file_read: path yok');
  if (!pathGuvenli(target)) throw new Error('file_read: izinsiz yol');
  if (!fs.existsSync(target)) throw new Error('file_read: dosya yok (' + target + ')');
  const buf = fs.readFileSync(target);
  if (payload.encoding === 'base64') return { ok: true, content: buf.toString('base64'), encoding: 'base64', bytes: buf.length };
  return { ok: true, content: buf.toString('utf8'), bytes: buf.length };
}

function execPowershell(payload) {
  return new Promise((resolve, reject) => {
    const script = payload.script || payload.command;
    if (!script) return reject(new Error('powershell: script yok'));
    execFile('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { timeout: payload.timeout_ms || 120000, maxBuffer: 20 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) return reject(new Error('powershell: ' + (stderr || err.message)));
        resolve({ ok: true, stdout: (stdout || '').slice(0, 1000000), stderr: (stderr || '').slice(0, 10000) });
      });
  });
}

async function processJob(job, tunnel) {
  const jid = job.JOB_ID;
  if (!await claimJob(jid)) return;
  console.log(new Date().toISOString() + ' [INFO] JOB ' + jid + ' claimed [' + (tunnel.name||'?') + ' type=' + (job.TYPE||'sql') + ' prio=' + (job.PRIORITY || 'def') + ']');
  const t0 = Date.now();
  try {
    let payload;
    try { payload = JSON.parse(job.PAYLOAD); }
    catch (e) { throw new Error('PAYLOAD parse: ' + extractErrMsg(e)); }

    const type = (job.TYPE || 'sql').toLowerCase();
    let result;

    if (type === 'file_write' || type === 'deploy') {
      result = await execFileWrite(payload);
    } else if (type === 'file_read') {
      result = execFileRead(payload);
    } else if (type === 'powershell') {
      result = await execPowershell(payload);
    } else if (type === 'ping' || type === 'test_ping') {
      result = { ok: true, pong: true, agent: tunnel.name || 'default', ts: Date.now() };
    } else {
      // sql / sql_query / varsayilan — mevcut davranis (DEGISMEDI)
      const sqlText = payload.sql || payload.query;
      if (!sqlText) throw new Error('No sql in payload');
      const rows = await dbQueryRetry(sqlText, payload.params || []);
      result = { rows: rows, count: rows.length };
    }

    const dur = Date.now() - t0;
    await postJobResult(jid, 'done', result, null, dur);
    const ozet = (result && result.count != null) ? (result.count + ' rows')
               : (result && result.bytes != null) ? (result.bytes + ' bytes') : 'ok';
    console.log(new Date().toISOString() + ' [INFO] JOB ' + jid + ' done (' + dur + 'ms, ' + ozet + ')');
  } catch (e) {
    const dur = Date.now() - t0;
    const msg = extractErrMsg(e);
    await postJobResult(jid, 'error', null, msg, dur);
    console.log(new Date().toISOString() + ' [ERROR] JOB ' + jid + ' failed (' + dur + 'ms): ' + msg);
  }
}

async function sendHeartbeat() {
  for (const t of TUNNELS) {
    try {
      await d1Query(
        'UPDATE VLX_TENANT_TUNNELS SET LAST_HEARTBEAT = strftime("%s","now") * 1000, STATUS = ? ' +
        'WHERE RECID = ?',
        ['connected', t.tunnel_recid]
      );
    } catch (e) { /* heartbeat best-effort */ }
  }
}

// Start polling AFTER HTTP server is listening
function startD1Polling() {
  console.log(new Date().toISOString() + ' [INFO] D1 polling started · table=' + D1_CFG.table + ' · poll=' + D1_CFG.poll_ms + 'ms · max=' + D1_CFG.max_parallel + ' · tenants=' + TUNNELS.length);
  for (const t of TUNNELS) {
    console.log(new Date().toISOString() + '   - ' + t.name + ' (tenant=' + t.tenant_recid + ', tunnel=' + t.tunnel_recid + ')');
  }
  // Her tunnel icin ayri poll interval
  for (const t of TUNNELS) {
    setInterval(() => { pollAndExecuteJobs(t).catch(() => {}); }, D1_CFG.poll_ms);
  }
  // Tek heartbeat interval (icinde tum tunnel'lara gonderir)
  setInterval(() => { sendHeartbeat().catch(() => {}); }, D1_CFG.heartbeat_ms);
}

// dbQueryRetry helper for D1 polling (uses same SQL pool as HTTP)
function dbQueryRetry(sqlText, params) {
  return new Promise((resolve, reject) => {
    sql.query(buildConnStr(), sqlText, params || [], (err, rows) => {
      if (err) reject(err); else resolve(rows || []);
    });
  });
}


server.listen(PORT, '0.0.0.0', () => {
  // Start D1 tunnel polling
  try { startD1Polling(); } catch(e) { console.log('D1 polling start failed: ' + e.message); }

  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║  ERPBI v10.0 Portal — Port ' + PORT + '                     ║');
  console.log('║  AX 2012 R3 | Config: config.json                    ║');
  console.log('║  API Key + JWT + Rate Limit + Kill Switch             ║');
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log('');
  console.log('⚙️  Config:');
  console.log('  SQL Server : ' + CONFIG.sql.server);
  console.log('  Database   : ' + CONFIG.sql.database);
  console.log('  Auth       : ' + CONFIG.sql.auth);
  console.log('  HTML       : ' + CONFIG.server.htmlFile);
  console.log('  Tunnel     : ' + CONFIG.tunnel.domain);
  console.log('');
  console.log('🔐 Güvenlik:');
  console.log('  API Keys  : ' + Object.keys(SECURITY.API_KEYS).length + ' adet');
  console.log('  Kullanıcı : ' + Object.keys(SECURITY.USERS).length + ' adet');
  console.log('  Rate Limit: ' + SECURITY.RATE_LIMIT + ' istek/dk');
  console.log('');
  console.log('📡 Endpoints (' + Object.keys(ROUTES).length + '):');
  Object.keys(ROUTES).forEach(r => console.log('  GET ' + r));
  console.log('');
  console.log('🆕 Admin Endpoints:');
  console.log('  POST /api/login           → JWT token al');
  console.log('  GET  /api/admin/config    → Ayarları oku');
  console.log('  POST /api/admin/config    → Ayarları kaydet');
  console.log('  POST /api/admin/kill      → Kill switch (admin)');
  console.log('  GET  /api/admin/status    → Sistem durumu (admin)');
  console.log('');
  console.log('🌐 Portal: https://' + CONFIG.tunnel.domain);
  console.log('   Local : http://localhost:' + PORT);
});

server.on('error', e => console.error('Server hatası:', e));
