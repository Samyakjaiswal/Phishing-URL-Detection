/* =========================================================
   PHISHGUARD — heuristic URL analysis engine
   Runs entirely client-side. No requests are made anywhere.
   Produces a 0–100 risk score from structural + lexical signals.
========================================================= */

const KNOWN_BRANDS = [
  'paypal','google','apple','microsoft','amazon','netflix','facebook',
  'instagram','bankofamerica','wellsfargo','chase','citibank','dhl',
  'fedex','ups','irs','outlook','office365','dropbox','linkedin',
  'whatsapp','steam','coinbase','binance'
];

const SUSPICIOUS_TLDS = [
  'tk','ml','ga','cf','gq','xyz','top','click','work','live','loan',
  'win','men','review','party','date','racing','download','stream'
];

const SHORTENERS = [
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
  'rebrand.ly','cutt.ly','shorte.st','adf.ly'
];

const CREDENTIAL_KEYWORDS = [
  'login','signin','verify','account','secure','update','confirm',
  'banking','password','authenticate','suspend','locked','urgent'
];

function buildChecks(rawUrl){
  const checks = [];
  let score = 0;
  let parsed;
  let normalized = rawUrl.trim();

  if (!/^[a-zA-Z]+:\/\//.test(normalized)) {
    normalized = 'http://' + normalized;
  }

  try {
    parsed = new URL(normalized);
  } catch (e) {
    return {
      score: 100,
      checks: [{
        level:'flag',
        title:'Malformed URL',
        detail:'This does not parse as a valid URL at all — treat with extreme caution.'
      }],
      anatomy: [],
      hostname: rawUrl,
      invalid:true
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullHref = parsed.href.toLowerCase();
  const path = (parsed.pathname + parsed.search).toLowerCase();
  const labels = hostname.split('.');

  // 1. Protocol check
  if (parsed.protocol === 'http:') {
    score += 12;
    checks.push({
      level:'warn',
      title:'No HTTPS encryption',
      detail:'Connection is unencrypted (http://). Legitimate login pages almost always use https.'
    });
  } else {
    checks.push({
      level:'pass',
      title:'HTTPS present',
      detail:'The URL uses an encrypted connection scheme.'
    });
  }

  // 2. IP address as hostname
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipPattern.test(hostname)) {
    score += 30;
    checks.push({
      level:'flag',
      title:'Raw IP address as host',
      detail:'The domain is a bare IP address instead of a name — a strong phishing indicator.'
    });
  }

  // 3. @ symbol trick (browser ignores everything before @)
  if (rawUrl.includes('@')) {
    score += 28;
    checks.push({
      level:'flag',
      title:'"@" symbol in URL',
      detail:'Browsers ignore everything before "@" — this can disguise the real destination.'
    });
  }

  // 4. Excessive subdomains (skip for raw IP hosts — not applicable)
  if (!ipPattern.test(hostname)) {
    if (labels.length >= 5) {
      score += 20;
      checks.push({
        level:'flag',
        title:'Excessive subdomains',
        detail:`Host has ${labels.length} segments. Long subdomain chains are used to bury the real domain.`
      });
    } else if (labels.length === 4) {
      score += 8;
      checks.push({
        level:'warn',
        title:'Multiple subdomains',
        detail:'More subdomain layers than a typical legitimate site.'
      });
    }
  }

  // 5. Punycode / homograph indicator
  if (hostname.includes('xn--')) {
    score += 25;
    checks.push({
      level:'flag',
      title:'Punycode encoding detected',
      detail:'Hostname uses punycode (xn--), often used to mimic letters from other alphabets.'
    });
  }

  // 6. Suspicious TLD
  const tld = labels[labels.length - 1];
  if (SUSPICIOUS_TLDS.includes(tld)) {
    score += 18;
    checks.push({
      level:'warn',
      title:`Risky top-level domain (.${tld})`,
      detail:'This TLD is disproportionately favored by free/disposable phishing infrastructure.'
    });
  }

  // 7. URL shortener
  const isShortener = SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s));
  if (isShortener) {
    score += 15;
    checks.push({
      level:'warn',
      title:'URL shortener detected',
      detail:'Shorteners hide the real destination until after you click.'
    });
  }

  // 8. Brand name impersonation (brand appears but isn't the actual registered domain)
  const registrableDomain = labels.slice(-2).join('.');
  let brandFlag = null;
  for (const brand of KNOWN_BRANDS) {
    if (hostname.includes(brand) && !registrableDomain.startsWith(brand + '.')) {
      brandFlag = brand;
      break;
    }
  }
  if (brandFlag) {
    score += 26;
    checks.push({
      level:'flag',
      title:`Brand impersonation: "${brandFlag}"`,
      detail:`"${brandFlag}" appears in the hostname but isn't the actual registered domain — classic lookalike pattern.`
    });
  }

  // 9. Hyphen-heavy domain
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 14;
    checks.push({
      level:'warn',
      title:'Hyphen-heavy domain',
      detail:`${hyphenCount} hyphens in the hostname — often used to chain fake brand/keyword combos.`
    });
  }

  // 10. Credential-harvesting keywords in path
  const foundKeywords = CREDENTIAL_KEYWORDS.filter(k => path.includes(k));
  if (foundKeywords.length >= 2) {
    score += 16;
    checks.push({
      level:'warn',
      title:'Credential-related keywords in path',
      detail:`Path contains urgency/login bait terms: ${foundKeywords.slice(0,3).join(', ')}.`
    });
  }

  // 11. Length check
  if (fullHref.length > 100) {
    score += 8;
    checks.push({
      level:'warn',
      title:'Unusually long URL',
      detail:'Long URLs can be used to obscure the true destination in the middle of the string.'
    });
  }

  // 12. No suspicious signals at all → add explicit pass
  if (checks.filter(c => c.level !== 'pass').length === 0) {
    checks.push({
      level:'pass',
      title:'No structural red flags',
      detail:'Domain structure, TLD, and path look ordinary.'
    });
  }

  score = Math.min(100, score);

  const anatomy = [
    { tag:'PROTOCOL', value: parsed.protocol.replace(':',''), flagged: parsed.protocol === 'http:' },
    { tag:'HOSTNAME', value: hostname, flagged: !!brandFlag || ipPattern.test(hostname) },
    { tag:'TLD', value: '.' + tld, flagged: SUSPICIOUS_TLDS.includes(tld) },
    { tag:'PATH', value: parsed.pathname || '/', flagged: foundKeywords.length >= 2 },
  ];
  if (parsed.search) {
    anatomy.push({ tag:'QUERY', value: parsed.search, flagged:false });
  }

  return { score, checks, anatomy, hostname, invalid:false };
}

function scoreToVerdict(score){
  if (score >= 55) return { tag:'HIGH RISK', cls:'danger', color:'#ff4757' };
  if (score >= 25) return { tag:'SUSPICIOUS', cls:'warn', color:'#ffa726' };
  return { tag:'LOOKS SAFE', cls:'safe', color:'#39ff8a' };
}

function adviceFor(verdictCls, hostname){
  if (verdictCls === 'danger') {
    return `Do not enter credentials or personal info on this page. Multiple strong phishing indicators were found around "${hostname}". If you received this link unexpectedly, verify directly with the organization through their official site or app instead of clicking through.`;
  }
  if (verdictCls === 'warn') {
    return `Some indicators are unusual for "${hostname}". It may still be legitimate, but double-check the spelling of the domain carefully and avoid entering sensitive information unless you're confident of the source.`;
  }
  return `No strong phishing signals were detected for "${hostname}". As always, stay alert for anything that asks you to urgently log in or confirm personal details.`;
}

function iconFor(level){
  if (level === 'flag') return '✕';
  if (level === 'warn') return '!';
  return '✓';
}

function runScan(rawUrl){
  const btn = document.getElementById('scanBtn');
  const label = btn.querySelector('.btn-label');
  btn.classList.add('scanning');
  label.textContent = 'SCANNING…';

  setTimeout(() => {
    const result = buildChecks(rawUrl);
    renderResult(rawUrl, result);
    btn.classList.remove('scanning');
    label.textContent = 'SCAN';
  }, 550);
}

function renderResult(rawUrl, result){
  const resultArea = document.getElementById('resultArea');
  resultArea.hidden = false;

  const { score, checks, anatomy, hostname, invalid } = result;
  const verdict = invalid
    ? { tag:'INVALID', cls:'danger', color:'#ff4757' }
    : scoreToVerdict(score);

  // Gauge
  const circumference = 2 * Math.PI * 84;
  const offset = circumference - (score / 100) * circumference;
  const gaugeFill = document.getElementById('gaugeFill');
  gaugeFill.style.stroke = verdict.color;
  requestAnimationFrame(() => {
    gaugeFill.style.strokeDashoffset = offset;
  });

  document.getElementById('gaugeScore').textContent = score;
  document.getElementById('gaugeScore').style.color = verdict.color;

  const verdictTag = document.getElementById('verdictTag');
  verdictTag.textContent = verdict.tag;
  verdictTag.style.color = verdict.color;
  verdictTag.style.background = verdict.color + '22';
  verdictTag.style.border = `1px solid ${verdict.color}55`;

  document.getElementById('verdictUrl').textContent = hostname;

  // Checks list
  const list = document.getElementById('checksList');
  list.innerHTML = '';
  checks.forEach(c => {
    const li = document.createElement('li');
    li.className = 'check-item';
    li.innerHTML = `
      <span class="check-icon ${c.level}">${iconFor(c.level)}</span>
      <span class="check-text"><strong>${c.title}</strong><span>${c.detail}</span></span>
    `;
    list.appendChild(li);
  });

  // Anatomy
  const anatomyRow = document.getElementById('anatomyRow');
  anatomyRow.innerHTML = '';
  anatomy.forEach(part => {
    const div = document.createElement('div');
    div.className = 'anatomy-part' + (part.flagged ? ' flagged' : '');
    div.innerHTML = `<span class="anatomy-tag">${part.tag}</span>${escapeHtml(part.value)}`;
    anatomyRow.appendChild(div);
  });

  // Advice
  const advicePanel = document.getElementById('advicePanel');
  advicePanel.className = 'advice-panel' + (verdict.cls !== 'safe' ? ' ' + verdict.cls : '');
  document.getElementById('adviceText').textContent = adviceFor(verdict.cls, hostname);

  resultArea.scrollIntoView({ behavior:'smooth', block:'start' });
}

function escapeHtml(str){
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---- wire up UI ----
const urlInputEl = document.getElementById('urlInput');
const consoleBarEl = document.querySelector('.console-bar');
urlInputEl.addEventListener('focus', () => consoleBarEl.classList.add('is-focused'));
urlInputEl.addEventListener('blur', () => consoleBarEl.classList.remove('is-focused'));

document.getElementById('scanBtn').addEventListener('click', () => {
  const val = document.getElementById('urlInput').value.trim();
  if (val) runScan(val);
});

document.getElementById('urlInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const val = e.target.value.trim();
    if (val) runScan(val);
  }
});

document.querySelectorAll('.chip').forEach(chip => {
  chip.addEventListener('click', () => {
    const sample = chip.getAttribute('data-sample');
    document.getElementById('urlInput').value = sample;
    runScan(sample);
  });
});

// live clock in topbar
function tick(){
  const el = document.getElementById('clock');
  const now = new Date();
  const t = now.toTimeString().slice(0,8);
  el.textContent = `SCANNER READY · ${t}`;
}
tick();
setInterval(tick, 1000);
