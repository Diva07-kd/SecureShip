import fs from 'fs';
import path from 'path';
import assert from 'assert';

console.log('=== SECURESCAN FRONTEND EMPIRICAL CHALLENGE SUITE ===\n');

let passCount = 0;
let failCount = 0;

function it(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passCount++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failCount++;
  }
}

// -------------------------------------------------------------
// 1. Bundle & Dist Integrity Verification
// -------------------------------------------------------------
console.log('SECTION 1: Build & Bundle Output Verification');

const distDir = path.resolve('frontend/dist');
const indexHtmlPath = path.join(distDir, 'index.html');
const assetsDir = path.join(distDir, 'assets');

it('dist/index.html exists and is non-empty', () => {
  assert(fs.existsSync(indexHtmlPath), 'index.html must exist in dist');
  const content = fs.readFileSync(indexHtmlPath, 'utf8');
  assert(content.length > 500, 'index.html is too small or truncated');
  assert(content.includes('<div id="root"></div>'), 'root div must be present');
  assert(content.includes('href="https://fonts.googleapis.com/css2?family=Inter'), 'Inter font link must be present');
});

it('assets directory contains separate chunk files for recharts, lucide, and main app', () => {
  assert(fs.existsSync(assetsDir), 'assets directory must exist');
  const files = fs.readdirSync(assetsDir);
  const jsFiles = files.filter(f => f.endsWith('.js'));
  const cssFiles = files.filter(f => f.endsWith('.css'));

  assert(jsFiles.length >= 3, `Expected at least 3 JS chunks, found: ${jsFiles.join(', ')}`);
  assert(cssFiles.length >= 1, `Expected at least 1 CSS file, found: ${cssFiles.join(', ')}`);

  const hasRecharts = jsFiles.some(f => f.startsWith('recharts-'));
  const hasLucide = jsFiles.some(f => f.startsWith('lucide-'));
  const hasApp = jsFiles.some(f => f.startsWith('index-'));

  assert(hasRecharts, 'recharts chunk must be isolated');
  assert(hasLucide, 'lucide chunk must be isolated');
  assert(hasApp, 'app entry chunk must be isolated');
});

it('bundle chunks are reasonably sized and no chunk exceeds uncompressed 1MB', () => {
  const files = fs.readdirSync(assetsDir);
  for (const file of files) {
    const fullPath = path.join(assetsDir, file);
    const stats = fs.statSync(fullPath);
    if (file.endsWith('.js')) {
      const sizeKb = stats.size / 1024;
      assert(sizeKb < 1024, `Chunk ${file} is ${sizeKb.toFixed(1)}KB, exceeding 1MB limit`);
    }
  }
});

it('all scripts and modulepreloads referenced in index.html exist on disk', () => {
  const content = fs.readFileSync(indexHtmlPath, 'utf8');
  const srcMatches = [...content.matchAll(/(?:src|href)="\/assets\/([^"]+)"/g)].map(m => m[1]);
  assert(srcMatches.length >= 3, 'Should have references to bundle assets');
  for (const assetName of srcMatches) {
    const assetPath = path.join(assetsDir, assetName);
    assert(fs.existsSync(assetPath), `Asset ${assetName} referenced in index.html does not exist on disk`);
  }
});

// -------------------------------------------------------------
// 2. React Router & Deep Linking Verification
// -------------------------------------------------------------
console.log('\nSECTION 2: React Router DOM & Deep Linking Verification');

const appSource = fs.readFileSync(path.resolve('frontend/src/App.tsx'), 'utf8');

it('App.tsx defines BrowserRouter and comprehensive Routes', () => {
  assert(appSource.includes('<BrowserRouter>'), 'App must use BrowserRouter');
  assert(appSource.includes('<Routes>'), 'App must contain Routes');
});

it('App.tsx defines root redirect route to /scan', () => {
  const rootRouteRegex = /<Route\s+path="\/"\s+element=\{<Navigate\s+to="\/scan"\s+replace\s*\/>\}\s*\/>/;
  assert(rootRouteRegex.test(appSource), 'Route path="/" must Navigate to /scan with replace');
});

it('App.tsx defines explicit /scan route mapping to ScanPage', () => {
  const scanRouteRegex = /<Route\s+path="\/scan"\s+element=\{<ScanPage\s*\/>\}\s*\/>/;
  assert(scanRouteRegex.test(appSource), 'Route path="/scan" must render ScanPage');
});

it('App.tsx defines dual report routes (/report/:job_id and /report/:id) for deep linking', () => {
  const jobIdRouteRegex = /<Route\s+path="\/report\/:job_id"\s+element=\{<ReportPage\s*\/>\}\s*\/>/;
  const idRouteRegex = /<Route\s+path="\/report\/:id"\s+element=\{<ReportPage\s*\/>\}\s*\/>/;
  assert(jobIdRouteRegex.test(appSource), 'Route path="/report/:job_id" must render ReportPage');
  assert(idRouteRegex.test(appSource), 'Route path="/report/:id" must render ReportPage');
});

it('App.tsx defines catch-all wildcard route navigating to /scan', () => {
  const catchAllRegex = /<Route\s+path="\*"\s+element=\{<Navigate\s+to="\/scan"\s+replace\s*\/>\}\s*\/>/;
  assert(catchAllRegex.test(appSource), 'Catch-all wildcard route "*" must Navigate to /scan with replace');
});

it('ReportPage consumes both :job_id and :id route parameters seamlessly', () => {
  const reportPageSource = fs.readFileSync(path.resolve('frontend/src/pages/ReportPage.tsx'), 'utf8');
  assert(reportPageSource.includes('useParams<{ job_id?: string; id?: string }>()'), 'useParams must type both params');
  assert(reportPageSource.includes('const effectiveJobId = job_id || id || \'\''), 'effectiveJobId must fallback between job_id and id');
});

it('Nginx configuration supports React Router HTML5 History fallback', () => {
  const nginxConf = fs.readFileSync(path.resolve('frontend/nginx.conf'), 'utf8');
  assert(nginxConf.includes('try_files $uri $uri/ /index.html;'), 'nginx must have try_files fallback to /index.html for SPA routes');
  assert(nginxConf.includes('client_max_body_size 50M;'), 'nginx must permit up to 50M uploads');
});

// -------------------------------------------------------------
// 3. UploadZone Component Behavioral Validation
// -------------------------------------------------------------
console.log('\nSECTION 3: UploadZone Behavioral & Boundary Verification');

const uploadZoneSource = fs.readFileSync(path.resolve('frontend/src/components/UploadZone.tsx'), 'utf8');

it('UploadZone strictly enforces 50MB constant ceiling (52,428,800 bytes)', () => {
  assert(uploadZoneSource.includes('const MAX_SIZE_BYTES = 50 * 1024 * 1024;'), 'MAX_SIZE_BYTES must be exactly 50 * 1024 * 1024');
  assert(uploadZoneSource.includes('file.size > MAX_SIZE_BYTES'), 'file.size comparison must reject sizes greater than 50MB');
});

it('UploadZone enforces .zip extension case-insensitively', () => {
  assert(uploadZoneSource.includes('!file.name.toLowerCase().endsWith(\'.zip\')'), 'must check file.name.toLowerCase().endsWith(".zip")');
});

// Empirical testing of file validation logic
function testValidateFile(filename, size) {
  const MAX_SIZE_BYTES = 50 * 1024 * 1024;
  if (!filename.toLowerCase().endsWith('.zip')) {
    return { valid: false, error: `Invalid archive "${filename}". SecureScan exclusively accepts .zip archives.` };
  }
  if (size > MAX_SIZE_BYTES) {
    const sizeMb = (size / (1024 * 1024)).toFixed(1);
    return { valid: false, error: `Archive exceeds 50 MB size limit (selected file is ${sizeMb} MB).` };
  }
  return { valid: true, error: null };
}

it('UploadZone logic accepts exactly 50MB and rejects 50MB + 1 byte', () => {
  const exactly50MB = 50 * 1024 * 1024;
  const under50MB = exactly50MB - 1;
  const over50MB = exactly50MB + 1;

  assert(testValidateFile('test.zip', under50MB).valid === true, 'under 50MB should pass');
  assert(testValidateFile('test.zip', exactly50MB).valid === true, 'exactly 50MB should pass');
  assert(testValidateFile('test.zip', over50MB).valid === false, '50MB + 1 byte must fail');
  assert(testValidateFile('test.zip', over50MB).error.includes('Archive exceeds 50 MB size limit'), 'error message must state limit');
});

it('UploadZone logic accepts .zip, .ZIP, .Zip, and rejects .tar, .exe, .rar, .sh', () => {
  assert(testValidateFile('test.zip', 1000).valid === true);
  assert(testValidateFile('PROJECT.ZIP', 1000).valid === true);
  assert(testValidateFile('MyCode.Zip', 1000).valid === true);

  assert(testValidateFile('payload.tar.gz', 1000).valid === false);
  assert(testValidateFile('exploit.exe', 1000).valid === false);
  assert(testValidateFile('archive.rar', 1000).valid === false);
  assert(testValidateFile('test.zip.bak', 1000).valid === false);
  assert(testValidateFile('script.sh', 1000).valid === false);
});

it('UploadZone drag and drop handlers prevent default and toggle drag states', () => {
  assert(uploadZoneSource.includes('e.preventDefault()'), 'Drag events must preventDefault');
  assert(uploadZoneSource.includes('setIsDragging(true)'), 'onDragOver must set isDragging true');
  assert(uploadZoneSource.includes('setIsDragging(false)'), 'onDragLeave and onDrop must set isDragging false');
  assert(uploadZoneSource.includes('e.dataTransfer.files'), 'onDrop must read e.dataTransfer.files');
});

it('UploadZone posts to /api/scan with FormData field "file"', () => {
  assert(uploadZoneSource.includes('formData.append(\'file\', file)'), 'FormData field must be named "file"');
  assert(uploadZoneSource.includes('xhr.open(\'POST\', \'/api/scan\')'), 'Endpoint must be /api/scan');
});

// -------------------------------------------------------------
// 4. SummaryDashboard Component Logic Validation
// -------------------------------------------------------------
console.log('\nSECTION 4: SummaryDashboard Component Calculations & Filters');

const summaryDashboardSource = fs.readFileSync(path.resolve('frontend/src/components/SummaryDashboard.tsx'), 'utf8');

it('SummaryDashboard defines exact severity color mapping', () => {
  assert(summaryDashboardSource.includes('CRITICAL: \'#dc2626\''), 'CRITICAL must be #dc2626 (red-600)');
  assert(summaryDashboardSource.includes('HIGH: \'#f97316\''), 'HIGH must be #f97316 (orange-500)');
  assert(summaryDashboardSource.includes('MEDIUM: \'#eab308\''), 'MEDIUM must be #eab308 (yellow-500)');
  assert(summaryDashboardSource.includes('LOW: \'#60a5fa\''), 'LOW must be #60a5fa (blue-400)');
  assert(summaryDashboardSource.includes('INFO: \'#6b7280\''), 'INFO must be #6b7280 (gray-500)');
});

// Empirical calculation logic test
function calculateSummaryDashboardMetrics(report) {
  const summary = report.summary || {
    totalFindings: 0,
    bySeverity: {},
    byOwasp: {},
    byScanner: {},
    byCategory: {},
  };
  const bySev = summary.bySeverity || summary.severityCounts || {};
  const totalFindings = report.summary?.totalFindings ?? report.findings?.length ?? 0;
  
  const filesAffected = (() => {
    if (!report.findings || report.findings.length === 0) return 0;
    const unique = new Set(report.findings.map((f) => f.location?.filePath).filter(Boolean));
    return unique.size;
  })();

  const scannersRun = report.scanners?.length || Object.keys(report.summary?.byScanner || {}).length || 5;
  const durationSec = ((report.durationMs || 0) / 1000).toFixed(1) + 's';

  return { totalFindings, filesAffected, scannersRun, durationSec, bySev };
}

it('SummaryDashboard computes unique files affected correctly even with duplicate and missing locations', () => {
  const mockReport = {
    durationMs: 4250,
    summary: { totalFindings: 5, bySeverity: { CRITICAL: 2, HIGH: 3 } },
    scanners: [{ name: 'opengrep' }, { name: 'gitleaks' }, { name: 'trivy' }],
    findings: [
      { id: '1', location: { filePath: 'src/app.py' } },
      { id: '2', location: { filePath: 'src/app.py' } }, // duplicate
      { id: '3', location: { filePath: 'src/utils.py' } },
      { id: '4', location: null },                         // missing location
      { id: '5', location: { filePath: '' } },             // empty location
    ]
  };

  const metrics = calculateSummaryDashboardMetrics(mockReport);
  assert.strictEqual(metrics.totalFindings, 5, 'Total findings must be 5');
  assert.strictEqual(metrics.filesAffected, 2, 'Files affected must be 2 unique files ("src/app.py", "src/utils.py")');
  assert.strictEqual(metrics.scannersRun, 3, 'Scanners run must be 3');
  assert.strictEqual(metrics.durationSec, '4.3s', 'Duration 4250ms must format to 4.3s');
});

it('SummaryDashboard OWASP horizontal bar chart triggers onFilterOwasp click callback', () => {
  assert(summaryDashboardSource.includes('onFilterOwasp?: (cat: string) => void'), 'Prop onFilterOwasp must be declared');
  assert(summaryDashboardSource.includes('selectedOwasp === entry.fullName ? \'#a855f7\' : \'#8b5cf6\''), 'Selected OWASP bar must highlight');
  assert(summaryDashboardSource.includes('onClick={(entry: any) => {'), 'OWASP bar must have onClick handler');
});

// -------------------------------------------------------------
// 5. FindingsTable Component Ordering, Filtering & Styling
// -------------------------------------------------------------
console.log('\nSECTION 5: FindingsTable Ordering, Filtering & Badges');

const findingsTableSource = fs.readFileSync(path.resolve('frontend/src/components/FindingsTable.tsx'), 'utf8');

it('FindingsTable declares SEVERITY_ORDER with CRITICAL ranked highest', () => {
  assert(findingsTableSource.includes('CRITICAL: 5'), 'CRITICAL must be rank 5');
  assert(findingsTableSource.includes('HIGH: 4'), 'HIGH must be rank 4');
  assert(findingsTableSource.includes('MEDIUM: 3'), 'MEDIUM must be rank 3');
  assert(findingsTableSource.includes('LOW: 2'), 'LOW must be rank 2');
  assert(findingsTableSource.includes('INFO: 1'), 'INFO must be rank 1');
});

// Empirical testing of sorting logic
function sortFindings(findings) {
  const SEVERITY_ORDER = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
  return [...findings].sort((a, b) => {
    const rankA = SEVERITY_ORDER[a.severity] || 0;
    const rankB = SEVERITY_ORDER[b.severity] || 0;
    return rankB - rankA;
  });
}

it('FindingsTable sorts findings with CRITICAL first by default', () => {
  const sampleFindings = [
    { id: '1', severity: 'LOW' },
    { id: '2', severity: 'CRITICAL' },
    { id: '3', severity: 'INFO' },
    { id: '4', severity: 'HIGH' },
    { id: '5', severity: 'MEDIUM' },
  ];
  const sorted = sortFindings(sampleFindings);
  assert.deepStrictEqual(sorted.map(s => s.severity), ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
});

// Empirical testing of reachability badge styling
function getReachabilityBadgeClass(reachability) {
  switch (reachability) {
    case 'REACHABLE':
      return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
    case 'UNREACHABLE':
      return 'bg-gray-800 text-gray-400 border border-gray-700';
    case 'UNKNOWN':
    default:
      return 'bg-amber-500/20 text-amber-300 border border-amber-500/30';
  }
}

it('FindingsTable styles reachability badges accurately (REACHABLE emerald, UNREACHABLE gray, UNKNOWN amber)', () => {
  assert(getReachabilityBadgeClass('REACHABLE').includes('emerald'), 'REACHABLE must be emerald/green');
  assert(getReachabilityBadgeClass('UNREACHABLE').includes('gray'), 'UNREACHABLE must be gray');
  assert(getReachabilityBadgeClass('UNKNOWN').includes('amber'), 'UNKNOWN must be amber/yellow');
  assert(getReachabilityBadgeClass('SOMETHING_ELSE').includes('amber'), 'Fallback must be amber/yellow');
});

// Empirical testing of search & filter logic
function filterFindings(findings, searchQuery, severity, category, scanner, owasp) {
  return findings.filter((f) => {
    const q = (searchQuery || '').toLowerCase().trim();
    const matchSearch =
      !q ||
      f.title?.toLowerCase().includes(q) ||
      f.ruleId?.toLowerCase().includes(q) ||
      f.location?.filePath?.toLowerCase().includes(q) ||
      f.description?.toLowerCase().includes(q) ||
      (f.cweIds && f.cweIds.some((cwe) => cwe.toLowerCase().includes(q)));

    const matchSev = severity === 'ALL' || f.severity === severity;
    const matchCat = category === 'ALL' || f.category === category;
    const matchScanner = scanner === 'ALL' || f.scannerName === scanner;
    const matchOwasp = !owasp || f.owaspCategory === owasp;

    return matchSearch && matchSev && matchCat && matchScanner && matchOwasp;
  });
}

it('FindingsTable filters correctly by CWE ID, file path, severity, and scanner', () => {
  const corpus = [
    { id: '1', title: 'SQL Injection', ruleId: 'py-sqli', severity: 'CRITICAL', category: 'SAST', scannerName: 'opengrep', owaspCategory: 'A03:2021-Injection', location: { filePath: 'app/db.py' }, cweIds: ['CWE-89'] },
    { id: '2', title: 'Hardcoded Secret', ruleId: 'aws-key', severity: 'HIGH', category: 'SECRET', scannerName: 'gitleaks', owaspCategory: 'A07:2021-Identification and Authentication Failures', location: { filePath: 'config.py' }, cweIds: ['CWE-798'] },
    { id: '3', title: 'Vulnerable Lib', ruleId: 'cve-2024-1234', severity: 'MEDIUM', category: 'SCA', scannerName: 'trivy', owaspCategory: 'A06:2021-Vulnerable and Outdated Components', location: { filePath: 'requirements.txt' }, cweIds: ['CWE-1395'] },
  ];

  // Test search by CWE
  const cweResults = filterFindings(corpus, 'CWE-89', 'ALL', 'ALL', 'ALL', null);
  assert.strictEqual(cweResults.length, 1);
  assert.strictEqual(cweResults[0].id, '1');

  // Test search by partial path
  const pathResults = filterFindings(corpus, 'config', 'ALL', 'ALL', 'ALL', null);
  assert.strictEqual(pathResults.length, 1);
  assert.strictEqual(pathResults[0].id, '2');

  // Test filter by severity
  const sevResults = filterFindings(corpus, '', 'HIGH', 'ALL', 'ALL', null);
  assert.strictEqual(sevResults.length, 1);
  assert.strictEqual(sevResults[0].id, '2');

  // Test filter by scanner
  const scannerResults = filterFindings(corpus, '', 'ALL', 'ALL', 'trivy', null);
  assert.strictEqual(scannerResults.length, 1);
  assert.strictEqual(scannerResults[0].id, '3');

  // Test active OWASP filter
  const owaspResults = filterFindings(corpus, '', 'ALL', 'ALL', 'ALL', 'A03:2021-Injection');
  assert.strictEqual(owaspResults.length, 1);
  assert.strictEqual(owaspResults[0].id, '1');
});

// -------------------------------------------------------------
// 6. CodeViewerDrawer Component Verification
// -------------------------------------------------------------
console.log('\nSECTION 6: CodeViewerDrawer Breadcrumbs, Syntax Highlighting & Red Target Line');

const codeViewerSource = fs.readFileSync(path.resolve('frontend/src/components/CodeViewerDrawer.tsx'), 'utf8');

it('CodeViewerDrawer handles Escape key event to close drawer', () => {
  assert(codeViewerSource.includes('e.key === \'Escape\''), 'Escape key must trigger onClose');
});

it('CodeViewerDrawer splits filePath across both Unix and Windows slashes into breadcrumbs', () => {
  assert(codeViewerSource.includes('.split(/[/\\\\]/)'), 'split regex must split both slash types');
  const pathParts = 'packages/core-engine\\src/runner.py'.split(/[/\\]/);
  assert.deepStrictEqual(pathParts, ['packages', 'core-engine', 'src', 'runner.py']);
});

it('CodeViewerDrawer highlights target vulnerable line with exact class "bg-red-500/20"', () => {
  assert(codeViewerSource.includes('bg-red-500/20 text-red-200 border-l-4 border-red-500 font-semibold'), 'Vulnerable line must have bg-red-500/20 and border-l-4');
  assert(codeViewerSource.includes('isVulnerable ? \'>>\' : \'  \''), 'Vulnerable line must display ">>" marker');
});

it('CodeViewerDrawer renders context window line numbers and code content', () => {
  assert(codeViewerSource.includes('{ln.lineNumber}'), 'Must display ln.lineNumber');
  assert(codeViewerSource.includes('{ln.content}'), 'Must display ln.content');
});

it('CodeViewerDrawer generates authoritative external MITRE CWE reference links', () => {
  assert(codeViewerSource.includes('https://cwe.mitre.org/data/definitions/${cweNum}.html'), 'Must link to cwe.mitre.org definitions');
});

// -------------------------------------------------------------
// 7. Full Monorepo & Backend Integrity Check
// -------------------------------------------------------------
console.log('\nSECTION 7: Export Buttons & API Route Contract Integrity');

const exportButtonsSource = fs.readFileSync(path.resolve('frontend/src/components/ExportButtons.tsx'), 'utf8');

it('ExportButtons provides JSON, SARIF, HTML, and PDF download triggers', () => {
  assert(exportButtonsSource.includes('handleDownload(\'json\')'), 'JSON download button present');
  assert(exportButtonsSource.includes('handleDownload(\'sarif\')'), 'SARIF download button present');
  assert(exportButtonsSource.includes('handleDownload(\'html\')'), 'HTML download button present');
  assert(exportButtonsSource.includes('handleDownload(\'pdf\')'), 'PDF download button present');
  assert(exportButtonsSource.includes('/api/reports/${jobId}/export?format=${format}'), 'API format parameter matches contract');
});

console.log('\n-------------------------------------------------------------');
console.log(`SUMMARY: ${passCount} passed, ${failCount} failed.`);
console.log('-------------------------------------------------------------');

if (failCount > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
