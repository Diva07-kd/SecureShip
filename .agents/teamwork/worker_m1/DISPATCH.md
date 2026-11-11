## 2026-11-07T08:37:18Z
You are worker_m1, a teamwork_worker.
Your working directory is: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\worker_m1
Read the original request at: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\ORIGINAL_REQUEST.md
Read PROJECT.md at: c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\PROJECT.md
Read explorer survey handoffs at:
- c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_survey_1\handoff.md
- c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_survey_3\handoff.md

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

EXCLUSIVE FILE OWNERSHIP:
You own and modify ONLY files under `frontend/`:
- `frontend/package.json`
- `frontend/index.html`
- `frontend/tailwind.config.js`
- `frontend/src/App.tsx`
- `frontend/src/pages/ScanPage.tsx`
- `frontend/src/pages/ReportPage.tsx`
- `frontend/src/components/Navbar.tsx`
- `frontend/src/components/Footer.tsx`
- `frontend/src/components/SummaryDashboard.tsx`
- `frontend/src/components/FindingsTable.tsx`
- `frontend/src/components/CodeViewerDrawer.tsx`
DO NOT modify any backend files.

TASKS TO IMPLEMENT:
1. `frontend/package.json`:
   - Add `"react-router-dom": "^6.28.0"`.
   - Run `npm --prefix frontend install` to install it cleanly.
2. `frontend/index.html`:
   - Add Google Fonts preconnect and link for Inter:
     `<link rel="preconnect" href="https://fonts.googleapis.com">`
     `<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>`
     `<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">`
3. `frontend/tailwind.config.js`:
   - Ensure font family includes Inter in `fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'], mono: [...] }`.
4. Create `frontend/src/components/Navbar.tsx`:
   - Modern dark header (`bg-gray-950/80 backdrop-blur border-b border-gray-800`).
   - Clickable brand link navigating to `/scan` (or `/`).
   - Displays live system status badge fetching `/api/health` (e.g. "5 engines ready").
5. Create `frontend/src/components/Footer.tsx`:
   - Clean dark footer with version and placement assessment metadata.
6. Create `frontend/src/pages/ScanPage.tsx`:
   - Hosts `UploadZone`.
   - Shows upload progress bar and scanning stage indicators.
   - Initiates 2-second polling to `GET /api/jobs/{id}`.
   - When job status is 'done', uses `navigate('/report/' + jobId)` to navigate to ReportPage.
   - If job status is 'failed', shows error banner with failure reason and retry button.
7. Create `frontend/src/pages/ReportPage.tsx`:
   - Reads `:job_id` from route params (`useParams`).
   - Fetches scan report from `GET /api/reports/{job_id}`.
   - If scan is still running (e.g. accessed directly while job in progress), polls `/api/jobs/{job_id}` every 2 seconds until done.
   - Handles 404 (Report Not Found) with a "Start New Scan" link.
   - Renders:
     - Header bar (target name, scan timestamp, job ID, total findings badge).
     - `ExportButtons` (JSON, SARIF, HTML, PDF).
     - `SummaryDashboard` with `onFilterOwasp` callback.
     - `FindingsTable` with filters and active OWASP category filter.
     - `CodeViewerDrawer` for selected finding.
8. Update `frontend/src/components/SummaryDashboard.tsx`:
   - Severity Donut chart colors (match spec exactly):
     - CRITICAL: `#dc2626` (red-600)
     - HIGH: `#f97316` (orange-500)
     - MEDIUM: `#eab308` (yellow-500)
     - LOW: `#60a5fa` (blue-400)
     - INFO: `#6b7280` (gray-500)
   - Stat cards (4 required):
     - Card 1: Total Findings (`report.summary?.totalFindings ?? report.findings?.length ?? 0`)
     - Card 2: Files Affected (`new Set(report.findings?.map(f => f.location?.filePath).filter(Boolean)).size`)
     - Card 3: Scanners Run (count of scanners, e.g. `report.scanners?.length || Object.keys(report.summary?.byScanner || {}).length || 5`)
     - Card 4: Scan Duration (`((report.durationMs || 0) / 1000).toFixed(1) + 's'`)
   - OWASP Top 10 horizontal bar chart:
     - Add `onClick` to the Bar/Chart so clicking an OWASP category triggers `onFilterOwasp(category)`.
     - Support props: `onFilterOwasp?: (cat: string) => void`, `selectedOwasp?: string | null`.
9. Update `frontend/src/components/FindingsTable.tsx`:
   - Reachability badge colors:
     - `REACHABLE`: green (`bg-emerald-500/20 text-emerald-400 border border-emerald-500/30`)
     - `UNREACHABLE`: gray (`bg-gray-800 text-gray-400 border border-gray-700`)
     - `UNKNOWN`: yellow (`bg-amber-500/20 text-amber-300 border border-amber-500/30`)
   - Accept `selectedOwasp` prop and filter findings accordingly, with a visible badge to clear the OWASP filter.
10. Update `frontend/src/components/CodeViewerDrawer.tsx`:
    - Segmented breadcrumb for `filePath` with folder/file styling.
    - Reachability colors: REACHABLE green (`text-emerald-400`), UNREACHABLE gray (`text-gray-400`), UNKNOWN yellow (`text-amber-300`).
    - Exact vulnerable line highlighted in red/orange (`bg-red-500/20 border-l-4 border-red-500`) with line numbers.
11. Update `frontend/src/App.tsx`:
    - Configure React Router with `BrowserRouter`:
      - Route `/` -> `<Navigate to="/scan" replace />`
      - Route `/scan` -> `<ScanPage />`
      - Route `/report/:job_id` -> `<ReportPage />`
      - Route `/report/:id` -> `<ReportPage />`
      - Route `*` -> `<Navigate to="/scan" replace />`
12. Build and Verify:
    - Run `npm --prefix frontend run build`
    - Verify 0 errors, 0 TypeScript errors.

When complete, write your handoff report to:
`c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\worker_m1\handoff.md`
Report back with build output and verified files.
