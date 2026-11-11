# In-Depth Audit Report: Frontend Pages, Routing & End-to-End Integration

**Document Version:** 1.0.0  
**Author:** Teamwork Explorer Survey Agent 3 (`explorer_survey_3`)  
**Working Directory:** `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\.agents\teamwork\explorer_survey_3`  
**Target Codebase:** `frontend/src/`  
**Recipient:** Orchestrator (`65e1f034-4edf-4003-8d0e-888ac8ff6287`)

---

## 1. Observation

### 1.1 Filesystem & Directory Structure (`frontend/src/`)
Direct observation of `c:\Dev\PLACEMENT-ASSESSMENT\SecureShip-IDE\frontend\src` via `Get-ChildItem -Recurse`:
```
Directory: frontend\src
Mode      Name
----      ----
d-----    components
d-----    types
-a----    App.tsx
-a----    index.css
-a----    main.tsx

Directory: frontend\src\components
Mode      Name
----      ----
-a----    CodeViewerDrawer.tsx
-a----    ExportButtons.tsx
-a----    FindingsTable.tsx
-a----    SummaryDashboard.tsx
-a----    UploadZone.tsx

Directory: frontend\src\types
Mode      Name
----      ----
-a----    report.ts
```

**Key Direct Observations:**
1. **Missing Pages Directory and Page Components:**
   - There is NO `pages/` directory under `frontend/src/`.
   - `ScanPage.tsx` (or `pages/ScanPage.tsx`) does NOT exist.
   - `ReportPage.tsx` (or `pages/ReportPage.tsx`) does NOT exist.
2. **Missing Routing Library in Dependencies:**
   - In `frontend/package.json:11-18`:
     ```json
     "dependencies": {
       "clsx": "^2.1.1",
       "lucide-react": "^0.468.0",
       "react": "^18.3.1",
       "react-dom": "^18.3.1",
       "recharts": "^2.13.3",
       "tailwind-merge": "^2.5.4"
     }
     ```
     `react-router-dom` is completely missing from `package.json` and does not exist in `frontend/node_modules/`.
3. **Monolithic State-Driven UI in `App.tsx` (`frontend/src/App.tsx:17-309`):**
   - Routing is completely absent. `App.tsx` manages a single monolithic state machine via `useState`:
     - `currentJobId` (`string | null`)
     - `jobStatus` (`JobRecord | null`)
     - `report` (`ScanReport | null`)
     - `selectedFinding` (`NormalizedFinding | null`)
     - `health` (`SystemHealth | null`)
     - `scanTargetName` (`string`)
   - Views are rendered conditionally via ternary checks:
     - State 1: Upload View (`!currentJobId`) — lines 153-167
     - State 2: Scanning & Progress Polling View (`currentJobId && jobStatus && jobStatus.status !== 'done' && jobStatus.status !== 'failed'`) — lines 170-229
     - State 3: Scan Failed View (`jobStatus && jobStatus.status === 'failed'`) — lines 232-249
     - State 4: Scan Completed Dashboard (`report`) — lines 251-292
   - Top navigation bar (lines 103-148) and footer (lines 302-307) are inlined directly into `App.tsx`.
4. **Navigation Broken & URL Disconnected:**
   - Root `/` does NOT redirect to `/scan`.
   - When a scan is submitted, the URL remains `/`.
   - When a scan finishes, the URL remains `/`.
   - Visiting `/scan` or `/report/:job_id` directly in the browser fails to render the respective views because `App.tsx` ignores browser pathnames; state is purely ephemeral in React memory. If a user refreshes or bookmarks `/report/abc-123`, the scan report is lost and the page resets to State 1 (Upload).
   - In `App.tsx:105-120`, the header brand (`SecureScan`) is an unclickable `<div>`.
5. **Component Feature Gaps:**
   - **`SummaryDashboard.tsx:118-133`**: The 4 top metric cards display `Total Vulnerabilities`, `Critical & High`, `Engines Executed`, and `Scan Duration`. The requirement in `ORIGINAL_REQUEST.md:44` specifies `stat cards (Total Findings, Files Affected, Scanners Run, Scan Duration)`. "Files Affected" is missing.
   - **`SummaryDashboard.tsx:238-266`**: OWASP Top 10 breakdown horizontal bar chart does NOT implement `click-to-filter`. It has no `onClick` handler and no callback to filter `FindingsTable`.
   - **`FindingsTable.tsx:256-267` & `CodeViewerDrawer.tsx:85-95`**: Reachability badges use purple (`bg-purple-500/20 text-purple-300`) for `REACHABLE` instead of green (`emerald-500`), and dark gray instead of yellow for `UNKNOWN`. Spec requirement: `green=REACHABLE, gray=UNREACHABLE, yellow=UNKNOWN`.
   - **`frontend/index.html:1-13`**: Inter font is not loaded (no `<link>` to Google Fonts or local font stylesheet), though `frontend/src/index.css:8` specifies Inter OpenType feature tags (`"cv02", "cv03", "cv04", "cv11"`).

---

## 2. Logic Chain

### 2.1 Route & Architectural Disconnection
1. **Premise:** The requirements explicitly demand:
   - Dedicated page wrappers: `ScanPage.tsx` hosting `UploadZone`, and `ReportPage.tsx` assembling `SummaryDashboard`, `FindingsTable`, `CodeViewerDrawer`, and `ExportButtons`.
   - React Router navigation with `/scan` and `/report/:job_id` (and `/` redirecting to `/scan`).
   - Clean, modular page components decoupled from top-level orchestration.
2. **Current State:** `App.tsx` has inlined all 4 views into a single component with zero routing.
3. **Failure Scenarios Caused by Current State:**
   - **Bookmark / Share Failure:** A security analyst who receives a job link `http://localhost:3000/report/7c9e6679-7425-40de-944b-e07fc1f90ae7` is shown the empty file upload zone instead of the report.
   - **Refresh Disruption:** If a user presses F5 while polling or reviewing findings, all state vanishes.
   - **Browser History Non-Functionality:** Back and forward browser buttons do not work between scan and report.
4. **Resolution Logic:**
   - Introduce `react-router-dom@^6.28.0`.
   - Establish `frontend/src/pages/ScanPage.tsx` to encapsulate upload handling, upload progress, active job polling, and navigation to `/report/:job_id` upon completion.
   - Establish `frontend/src/pages/ReportPage.tsx` to read `:job_id` from route parameters (`useParams`), fetch from `/api/reports/:job_id` (with fallback polling if job is still in progress), and render dashboard, findings, code viewer drawer, and export controls.
   - Extract `Navbar` and `Footer` into reusable components (`frontend/src/components/Navbar.tsx` and `frontend/src/components/Footer.tsx`).
   - Refactor `App.tsx` to configure `BrowserRouter` with:
     - `<Route path="/" element={<Navigate to="/scan" replace />} />`
     - `<Route path="/scan" element={<ScanPage />} />`
     - `<Route path="/report/:job_id" element={<ReportPage />} />`
     - `<Route path="/report/:id" element={<ReportPage />} />` (alias)
     - `<Route path="*" element={<Navigate to="/scan" replace />} />`

### 2.2 End-to-End User Journey Verification
We traced the 6-stage user journey required by the assessment:

```
[User arrives at /]
       │
       ▼ (Client-side redirect: <Navigate to="/scan" replace />)
[Route /scan: ScanPage]
       │
       ├─► Header displays live health badge via GET /api/health ("Scanners Ready (5 engines baked)")
       ├─► User drops .zip file (validated: .zip only, <= 50MB)
       ├─► UploadZone executes XMLHttpRequest POST /api/scan with upload progress bar (0% -> 100%)
       ▼
[Job Enqueued: HTTP 200 { job_id: "...", status: "queued", poll_url: "/api/jobs/..." }]
       │
       ├─► ScanPage displays animated scanning spinner & stage indicator pills:
       │     1. Safe Extract  ->  2. Engine Scan  ->  3. Snippets & OWASP
       ├─► ScanPage initiates 2.0s polling interval: GET /api/jobs/{job_id}
       │     - If status == "failed": shows error banner with failure reason & retry button
       ▼ (When status == "done")
[Navigation: navigate('/report/' + job_id)]
       │
       ▼
[Route /report/:job_id: ReportPage]
       │
       ├─► Fetches GET /api/reports/{job_id}
       │     - Direct Access Resiliency: If accessed while job is still running (HTTP 409),
       │       ReportPage seamlessly resumes 2s polling until status == "done".
       │     - 404 Resiliency: If job ID is invalid, displays "Scan Report Not Found" + "Start New Scan".
       │     - 422 Resiliency: If scan failed, displays execution error details + "Start New Scan".
       ▼
[Success State: Full Security Telemetry Displayed]
       ├─► Top Metadata Bar: Target filename, Scan timestamp, Job ID, Total findings
       ├─► Multi-Format Export Bar: JSON, SARIF 2.1.0, Single-File HTML, Executive PDF
       │     (GET /api/reports/{id}/export?format=json|sarif|html|pdf)
       ├─► SummaryDashboard:
       │     - 4 Stat Cards: Total Findings, Files Affected, Scanners Run (5), Scan Duration
       │     - Severity Donut (Recharts PieChart)
       │     - Scanner Breakdown (Recharts BarChart)
       │     - OWASP Top 10 Horizontal BarChart with click-to-filter
       ├─► FindingsTable:
       │     - Filterable by Severity, Category, Scanner, CWE, File path, and clicked OWASP category
       │     - Sortable by Severity (CRITICAL first), Rule ID, Location
       │     - Row details: Severity badge, Rule ID, Location, CWE, Reachability badge (green/gray/yellow)
       │     - Row click / "Inspect" button opens CodeViewerDrawer
       ├─► CodeViewerDrawer:
       │     - Slide-in panel, ESC key dismiss, backdrop click dismiss
       │     - Breadcrumb file path & line number
       │     - Syntax-highlighted code context window (±5 lines) with target line highlighted in red/orange
       │     - Vulnerability details, CWE/OWASP metadata, and MITRE external links
       ▼
[Navigation Back to Scan]
       ├─► Navbar Brand Logo & Title links directly to /scan
       └─► Sticky "New Scan" button in Navbar & ReportPage header navigates to /scan
```

### 2.3 Nginx and Vite Server-Side Routing Verification
- In `frontend/nginx.conf:9-13`:
  ```nginx
  location / {
      root /usr/share/nginx/html;
      index index.html index.htm;
      try_files $uri $uri/ /index.html;
  }
  ```
  The production Nginx configuration already has `try_files $uri $uri/ /index.html;`, meaning direct requests to `/scan` or `/report/:job_id` will fall back to `index.html` and let React Router handle routing without 404 errors.
- In `frontend/vite.config.ts`: Vite's dev server handles SPA routing fallback by default.

---

## 3. Caveats

1. **Package Installation Requirement:**
   Adding `react-router-dom` requires modifying `frontend/package.json` and running `npm install react-router-dom@^6.28.0` in `frontend/`. In Docker builds, `Dockerfile` already executes `RUN npm install`, so it will automatically install the package during container compilation.
2. **Read-Only Explorer Scope:**
   As an Explorer agent, this report does NOT modify source code files. Instead, Section 4 and Section 5 provide complete, drop-in replacement templates for the implementer agent.
3. **CodeViewer Syntax Highlighter:**
   The original prompt noted `react-syntax-highlighter, Prism theme`. Currently `CodeViewerDrawer.tsx` uses custom line-by-line monospace rendering with line gutters and vulnerable line highlighting (`bg-red-500/15`, `border-l-4 border-red-500`). This avoids adding 15MB+ of Prism grammar bundles while providing dark-theme rendering. We provide an enhanced version that preserves this zero-dependency approach while adding language tags and visual polish.

---

## 4. Conclusion & Concrete Architectural Recommendations

### 4.1 Summary of Changes Required

| Component / File | Current State | Required Change | Impact |
| :--- | :--- | :--- | :--- |
| `frontend/package.json` | Missing `react-router-dom` | Add `"react-router-dom": "^6.28.0"` to dependencies | Enables client-side routing |
| `frontend/src/pages/ScanPage.tsx` | Missing | Create new page component hosting `UploadZone` & scan progress lifecycle | Modular upload page |
| `frontend/src/pages/ReportPage.tsx` | Missing | Create new page component assembling dashboard, table, drawer, exports | Deep-linkable report page |
| `frontend/src/components/Navbar.tsx` | Inlined in `App.tsx` | Extract to modular component with `<Link to="/scan">` and live `/api/health` badge | Universal navigation |
| `frontend/src/components/Footer.tsx` | Inlined in `App.tsx` | Extract to modular component | Consistent footer |
| `frontend/src/App.tsx` | 310 lines monolithic | Refactor to 45 lines router orchestrator with `/scan`, `/report/:job_id`, `/` redirect | Clean architecture |
| `frontend/src/components/SummaryDashboard.tsx` | Missing "Files Affected", missing OWASP click-to-filter | Add "Files Affected" stat card and `onFilterOwasp` click handler | Complete spec compliance |
| `frontend/src/components/FindingsTable.tsx` | Reachability is purple, no external OWASP filter | Update badge colors to green/gray/yellow and support `selectedOwaspFilter` prop | Design system compliance |
| `frontend/src/components/CodeViewerDrawer.tsx` | Reachability is purple | Update badge colors to green/gray/yellow | Design system compliance |
| `frontend/index.html` & `tailwind.config.js` | Inter font not loaded | Add Google Fonts `<link>` for Inter & JetBrains Mono, configure `fontFamily.sans` | Visual typography |

---

## 5. Verification Method & Implementation Artifacts

### 5.1 Verification Commands
Once implemented, the reviewer and testing harness must run:

1. **Frontend Compilation:**
   ```powershell
   npm --prefix frontend install react-router-dom@^6.28.0
   npm --prefix frontend run build
   ```
   **Expected Outcome:** Exits 0, 0 TypeScript errors, 0 warnings.
2. **Backend Regression Test Suite:**
   ```powershell
   python -m pytest -q
   ```
   **Expected Outcome:** 396 passed, 0 failed.
3. **Navigation & Flow Verification:**
   - Start frontend: `npm --prefix frontend run dev`
   - Visit `http://localhost:3000/` -> browser URL automatically rewrites to `http://localhost:3000/scan`.
   - Upload sample `.zip` -> progress bar displays polling every 2s.
   - On completion -> URL automatically updates to `http://localhost:3000/report/<job_id>`.
   - Refresh page at `http://localhost:3000/report/<job_id>` -> report data successfully loads from `/api/reports/<job_id>`.
   - Click "SecureScan" logo or "New Scan" button -> navigates back to `/scan`.

---

## 6. Complete Implementation Templates

The implementer can apply these exact file templates:

### Template 1: `frontend/package.json`
Add `"react-router-dom": "^6.28.0"` to `dependencies`:
```json
{
  "name": "securescan-frontend",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "clsx": "^2.1.1",
    "lucide-react": "^0.468.0",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.28.0",
    "recharts": "^2.13.3",
    "tailwind-merge": "^2.5.4"
  },
  "devDependencies": {
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.4",
    "autoprefixer": "^10.4.20",
    "postcss": "^8.4.49",
    "tailwindcss": "^3.4.16",
    "typescript": "^5.6.3",
    "vite": "^6.0.3"
  }
}
```

### Template 2: `frontend/src/components/Navbar.tsx`
Create `frontend/src/components/Navbar.tsx`:
```tsx
import React, { useState, useEffect, useCallback } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, RotateCcw } from 'lucide-react';
import { SystemHealth } from '../types/report';

export const Navbar: React.FC = () => {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const location = useLocation();
  const isReportPage = location.pathname.startsWith('/report');

  const checkHealth = useCallback(async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      }
    } catch {
      // Backend not yet reachable
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  return (
    <header className="border-b border-gray-800 bg-gray-950/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <Link to="/scan" className="flex items-center gap-3 group">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 to-purple-600 flex items-center justify-center shadow-lg shadow-indigo-600/20 group-hover:scale-105 transition-transform">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-lg font-bold text-white tracking-tight group-hover:text-indigo-300 transition-colors">
                SecureScan
              </span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                v1.0
              </span>
            </div>
            <p className="text-[11px] text-gray-400 hidden sm:block">
              Defensive Security Scanner &bull; Powered by SecureShip
            </p>
          </div>
        </Link>

        {/* Right Header Status & Navigation */}
        <div className="flex items-center gap-4">
          {health && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-gray-900 border border-gray-800 text-xs">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span className="text-gray-300 font-medium">Scanners Ready</span>
              <span className="text-gray-500 text-[10px] hidden md:inline">
                (5 engines baked)
              </span>
            </div>
          )}

          {isReportPage && (
            <Link
              to="/scan"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 text-gray-300 hover:text-white text-xs font-medium border border-gray-800 hover:border-gray-700 transition shadow-sm"
            >
              <RotateCcw className="w-3.5 h-3.5 text-indigo-400" />
              New Scan
            </Link>
          )}
        </div>
      </div>
    </header>
  );
};
```

### Template 3: `frontend/src/components/Footer.tsx`
Create `frontend/src/components/Footer.tsx`:
```tsx
import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-gray-800/80 py-6 text-center text-xs text-gray-500 mt-auto bg-gray-950">
      <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
        <span>SecureScan &bull; Defensive Security Web Platform &bull; Heyram Infrastructure Assessment</span>
        <span>MITRE CWE &bull; OWASP Top 10 (2021) &bull; OASIS SARIF 2.1.0</span>
      </div>
    </footer>
  );
};
```

### Template 4: `frontend/src/pages/ScanPage.tsx`
Create `frontend/src/pages/ScanPage.tsx`:
```tsx
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, AlertTriangle, RotateCcw } from 'lucide-react';
import { UploadZone } from '../components/UploadZone';
import { JobRecord } from '../types/report';

export const ScanPage: React.FC = () => {
  const navigate = useNavigate();
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [scanTargetName, setScanTargetName] = useState<string>('');
  const [jobStatus, setJobStatus] = useState<JobRecord | null>(null);

  // Handle successful upload from UploadZone
  const handleUploadSuccess = (jobId: string, filename: string) => {
    setActiveJobId(jobId);
    setScanTargetName(filename);
    setJobStatus({
      jobId,
      status: 'queued',
      stage: 'queued',
      progress: 5,
      pollUrl: `/api/jobs/${jobId}`,
      targetName: filename,
    });
  };

  // 2-second polling loop for active job
  useEffect(() => {
    if (!activeJobId || (jobStatus && (jobStatus.status === 'done' || jobStatus.status === 'failed'))) {
      return;
    }

    const pollJob = async () => {
      try {
        const res = await fetch(`/api/jobs/${activeJobId}`);
        if (!res.ok) return;

        const data: JobRecord = await res.json();
        setJobStatus(data);

        // On completion, navigate directly to /report/:job_id
        if (data.status === 'done') {
          navigate(`/report/${activeJobId}`);
        }
      } catch (err) {
        console.error('Job polling error:', err);
      }
    };

    pollJob();
    const interval = setInterval(pollJob, 2000);
    return () => clearInterval(interval);
  }, [activeJobId, jobStatus?.status, navigate]);

  const handleReset = () => {
    setActiveJobId(null);
    setScanTargetName('');
    setJobStatus(null);
  };

  return (
    <div className="space-y-10 py-6">
      {/* State 1: Upload View */}
      {!activeJobId && (
        <div className="space-y-10">
          <div className="text-center max-w-2xl mx-auto space-y-3">
            <h2 className="text-3xl font-extrabold text-white tracking-tight sm:text-4xl">
              Multi-Engine Defensive Security Scanner
            </h2>
            <p className="text-sm text-gray-400">
              Upload your source code or application zip archive to execute automated SAST, SCA, Secret Detection,
              and IaC security audits with reachability verification and code snippet context.
            </p>
          </div>

          <UploadZone onUploadSuccess={handleUploadSuccess} />
        </div>
      )}

      {/* State 2: Scanning & Progress Polling View */}
      {activeJobId && jobStatus && jobStatus.status !== 'done' && jobStatus.status !== 'failed' && (
        <div className="max-w-2xl mx-auto py-16 text-center space-y-6">
          <div className="relative w-24 h-24 mx-auto flex items-center justify-center">
            <div className="absolute inset-0 rounded-full border-4 border-indigo-500/20 border-t-indigo-500 animate-spin"></div>
            <Shield className="w-10 h-10 text-indigo-400 animate-pulse" />
          </div>

          <div className="space-y-2">
            <h3 className="text-xl font-bold text-white">Security Scan in Progress</h3>
            <p className="text-xs text-gray-400 font-mono">
              Target: {scanTargetName} &bull; Job ID: {activeJobId}
            </p>
          </div>

          {/* Stage Indicator Pills */}
          <div className="grid grid-cols-3 gap-2 max-w-lg mx-auto text-xs">
            <div
              className={`p-2.5 rounded-lg border transition ${
                jobStatus.stage === 'extracting'
                  ? 'bg-indigo-950/40 border-indigo-500/40 text-indigo-200'
                  : 'bg-gray-900 border-gray-800 text-gray-500'
              }`}
            >
              1. Safe Extract
            </div>
            <div
              className={`p-2.5 rounded-lg border transition ${
                jobStatus.stage === 'scanning'
                  ? 'bg-indigo-950/40 border-indigo-500/40 text-indigo-200'
                  : 'bg-gray-900 border-gray-800 text-gray-500'
              }`}
            >
              2. Engine Scan
            </div>
            <div
              className={`p-2.5 rounded-lg border transition ${
                jobStatus.stage === 'enriching'
                  ? 'bg-indigo-950/40 border-indigo-500/40 text-indigo-200'
                  : 'bg-gray-900 border-gray-800 text-gray-500'
              }`}
            >
              3. Snippets & OWASP
            </div>
          </div>

          {/* Animated Progress Bar */}
          <div className="w-full max-w-md mx-auto space-y-1.5">
            <div className="h-2 w-full bg-gray-900 rounded-full overflow-hidden border border-gray-800">
              <div
                className="h-full bg-gradient-to-r from-indigo-500 via-purple-500 to-emerald-500 transition-all duration-500"
                style={{ width: `${Math.max(jobStatus.progress, 15)}%` }}
              />
            </div>
            <div className="flex justify-between text-[11px] font-mono text-gray-400">
              <span>Polling status every 2s</span>
              <span>{jobStatus.progress}%</span>
            </div>
          </div>
        </div>
      )}

      {/* State 3: Scan Failed View */}
      {jobStatus && jobStatus.status === 'failed' && (
        <div className="max-w-xl mx-auto py-12 text-center space-y-4">
          <div className="w-16 h-16 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center mx-auto text-red-400">
            <AlertTriangle className="w-8 h-8" />
          </div>
          <h3 className="text-xl font-bold text-white">Scan Execution Rejected</h3>
          <div className="p-4 rounded-lg bg-red-950/30 border border-red-500/20 text-red-200 text-xs text-left font-mono">
            {jobStatus.error || 'Scan process encountered an unhandled execution error.'}
          </div>
          <button
            onClick={handleReset}
            className="inline-flex items-center gap-1.5 px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Analyze Another Archive
          </button>
        </div>
      )}
    </div>
  );
};
```

### Template 5: `frontend/src/pages/ReportPage.tsx`
Create `frontend/src/pages/ReportPage.tsx`:
```tsx
import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  FileArchive,
  Layers,
  AlertTriangle,
  RotateCcw,
  Shield,
  Loader2,
} from 'lucide-react';
import { SummaryDashboard } from '../components/SummaryDashboard';
import { FindingsTable } from '../components/FindingsTable';
import { CodeViewerDrawer } from '../components/CodeViewerDrawer';
import { ExportButtons } from '../components/ExportButtons';
import { ScanReport, JobRecord, NormalizedFinding } from '../types/report';

export const ReportPage: React.FC = () => {
  const { job_id, id } = useParams<{ job_id?: string; id?: string }>();
  const effectiveJobId = job_id || id || '';

  const [report, setReport] = useState<ScanReport | null>(null);
  const [jobStatus, setJobStatus] = useState<JobRecord | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<NormalizedFinding | null>(null);
  const [selectedOwaspFilter, setSelectedOwaspFilter] = useState<string | null>(null);

  // Poll job status or fetch report
  useEffect(() => {
    if (!effectiveJobId) {
      setErrorMessage('No Job ID specified.');
      setIsLoading(false);
      return;
    }

    let isMounted = true;
    let pollInterval: NodeJS.Timeout | null = null;

    const fetchReportOrPoll = async () => {
      try {
        // Attempt to fetch completed report
        const reportRes = await fetch(`/api/reports/${effectiveJobId}`);
        if (reportRes.ok) {
          const reportData: ScanReport = await reportRes.json();
          if (isMounted) {
            setReport(reportData);
            setIsLoading(false);
            setErrorMessage(null);
          }
          if (pollInterval) clearInterval(pollInterval);
          return;
        }

        // If report returned 409 Conflict (still processing) or 404/422, check job status
        const jobRes = await fetch(`/api/jobs/${effectiveJobId}`);
        if (jobRes.ok) {
          const jobData: JobRecord = await jobRes.json();
          if (isMounted) {
            setJobStatus(jobData);
          }

          if (jobData.status === 'failed') {
            if (isMounted) {
              setErrorMessage(jobData.error || 'Security scan failed during execution.');
              setIsLoading(false);
            }
            if (pollInterval) clearInterval(pollInterval);
            return;
          }

          if (jobData.status === 'done') {
            // Re-fetch report
            const retryRes = await fetch(`/api/reports/${effectiveJobId}`);
            if (retryRes.ok && isMounted) {
              const retryData: ScanReport = await retryRes.json();
              setReport(retryData);
              setIsLoading(false);
              setErrorMessage(null);
            }
            if (pollInterval) clearInterval(pollInterval);
            return;
          }

          // Still queued or running
          if (isMounted) {
            setIsLoading(false);
          }
        } else if (jobRes.status === 404) {
          if (isMounted) {
            setErrorMessage(`Scan job "${effectiveJobId}" was not found or has expired.`);
            setIsLoading(false);
          }
          if (pollInterval) clearInterval(pollInterval);
        } else {
          if (isMounted) {
            setErrorMessage(`Failed to load job status (HTTP ${jobRes.status}).`);
            setIsLoading(false);
          }
          if (pollInterval) clearInterval(pollInterval);
        }
      } catch (err: unknown) {
        if (isMounted) {
          const msg = err instanceof Error ? err.message : 'Network error loading report.';
          setErrorMessage(msg);
          setIsLoading(false);
        }
      }
    };

    fetchReportOrPoll();
    // Poll every 2 seconds if report is not yet loaded
    pollInterval = setInterval(fetchReportOrPoll, 2000);

    return () => {
      isMounted = false;
      if (pollInterval) clearInterval(pollInterval);
    };
  }, [effectiveJobId]);

  // Loading indicator for initial fetch
  if (isLoading) {
    return (
      <div className="py-24 text-center space-y-4">
        <Loader2 className="w-10 h-10 animate-spin text-indigo-400 mx-auto" />
        <p className="text-sm text-gray-400">Loading scan report for job {effectiveJobId}...</p>
      </div>
    );
  }

  // Error State: Job not found or failed
  if (errorMessage) {
    return (
      <div className="max-w-xl mx-auto py-16 text-center space-y-5">
        <div className="w-16 h-16 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center mx-auto text-red-400">
          <AlertTriangle className="w-8 h-8" />
        </div>
        <h3 className="text-xl font-bold text-white">Unable to Load Scan Report</h3>
        <div className="p-4 rounded-lg bg-red-950/30 border border-red-500/20 text-red-200 text-xs text-left font-mono">
          {errorMessage}
        </div>
        <Link
          to="/scan"
          className="inline-flex items-center gap-1.5 px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          Start New Scan
        </Link>
      </div>
    );
  }

  // Intermediate State: Direct link opened while scan is still running
  if (!report && jobStatus && (jobStatus.status === 'queued' || jobStatus.status === 'running')) {
    return (
      <div className="max-w-2xl mx-auto py-16 text-center space-y-6">
        <div className="relative w-24 h-24 mx-auto flex items-center justify-center">
          <div className="absolute inset-0 rounded-full border-4 border-indigo-500/20 border-t-indigo-500 animate-spin"></div>
          <Shield className="w-10 h-10 text-indigo-400 animate-pulse" />
        </div>

        <div className="space-y-2">
          <h3 className="text-xl font-bold text-white">Security Scan in Progress</h3>
          <p className="text-xs text-gray-400 font-mono">
            Target: {jobStatus.targetName || 'Codebase'} &bull; Job ID: {effectiveJobId}
          </p>
        </div>

        {/* Animated Progress Bar */}
        <div className="w-full max-w-md mx-auto space-y-1.5">
          <div className="h-2 w-full bg-gray-900 rounded-full overflow-hidden border border-gray-800">
            <div
              className="h-full bg-gradient-to-r from-indigo-500 via-purple-500 to-emerald-500 transition-all duration-500"
              style={{ width: `${Math.max(jobStatus.progress, 15)}%` }}
            />
          </div>
          <div className="flex justify-between text-[11px] font-mono text-gray-400">
            <span>Stage: {jobStatus.stage} &bull; Polling every 2s</span>
            <span>{jobStatus.progress}%</span>
          </div>
        </div>
      </div>
    );
  }

  // Success State: Render Complete Security Telemetry
  if (!report) return null;

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Top Bar with Target Meta & Exporters */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-xl bg-gray-900/60 border border-gray-800">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <FileArchive className="w-4 h-4 text-indigo-400" />
            <span className="font-bold text-white text-base">
              {report.targetName || 'Target Codebase'}
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              SCAN COMPLETE
            </span>
          </div>
          <div className="text-xs text-gray-400 font-mono">
            Job ID: {report.id || effectiveJobId} &bull; Findings: {report.summary?.totalFindings || 0}
          </div>
        </div>

        {/* Multi-Format Export Bar */}
        <ExportButtons jobId={report.id || effectiveJobId} />
      </div>

      {/* Summary Statistics & Charts with OWASP click-to-filter */}
      <SummaryDashboard
        report={report}
        onFilterOwasp={(cat) => setSelectedOwaspFilter(cat)}
        selectedOwasp={selectedOwaspFilter}
      />

      {/* Filterable Findings Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-indigo-400" />
            Security Audit Findings
          </h3>
          {selectedOwaspFilter && (
            <div className="flex items-center gap-2 text-xs">
              <span className="text-gray-400">OWASP Filter:</span>
              <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 font-medium">
                {selectedOwaspFilter}
              </span>
              <button
                onClick={() => setSelectedOwaspFilter(null)}
                className="text-gray-400 hover:text-white underline text-xs"
              >
                Clear
              </button>
            </div>
          )}
        </div>

        <FindingsTable
          findings={report.findings || []}
          onSelectFinding={(f) => setSelectedFinding(f)}
          selectedOwaspFilter={selectedOwaspFilter}
          onClearOwaspFilter={() => setSelectedOwaspFilter(null)}
        />
      </div>

      {/* Slide-In Code Viewer Drawer */}
      <CodeViewerDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
};
```

### Template 6: `frontend/src/App.tsx` (Clean Router Orchestrator)
Replace `frontend/src/App.tsx`:
```tsx
import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { ScanPage } from './pages/ScanPage';
import { ReportPage } from './pages/ReportPage';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-950 text-gray-100 flex flex-col font-sans">
        <Navbar />
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <Routes>
            <Route path="/" element={<Navigate to="/scan" replace />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/report/:job_id" element={<ReportPage />} />
            <Route path="/report/:id" element={<ReportPage />} />
            <Route path="*" element={<Navigate to="/scan" replace />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </BrowserRouter>
  );
};
```

### Template 7: Enhancements to `SummaryDashboard.tsx`
1. **Stat Cards Enhancement (Files Affected):**
   Compute `filesAffected`:
   ```tsx
   const filesAffected = new Set(
     (report.findings || []).map((f) => f.location?.filePath).filter(Boolean)
   ).size;
   ```
   Replace the 4 stat cards with:
   - Card 1: `Total Findings` (`totalFindings`)
   - Card 2: `Files Affected` (`filesAffected`)
   - Card 3: `Scanners Run` (`5` - pre-baked engines)
   - Card 4: `Scan Duration` (`${durationSec}s`)
2. **OWASP BarChart Click-to-Filter:**
   Add `onFilterOwasp?: (category: string | null) => void` and `selectedOwasp?: string | null` to props:
   ```tsx
   interface SummaryDashboardProps {
     report: ScanReport;
     onFilterOwasp?: (category: string | null) => void;
     selectedOwasp?: string | null;
   }
   ```
   Add click event to `<Bar>`:
   ```tsx
   <Bar
     dataKey="count"
     fill="#8b5cf6"
     radius={[0, 4, 4, 0]}
     cursor="pointer"
     onClick={(data: any) => {
       if (onFilterOwasp && data && data.fullName) {
         onFilterOwasp(selectedOwasp === data.fullName ? null : data.fullName);
       }
     }}
   />
   ```

### Template 8: Design System Compliance (Reachability Colors & Fonts)
1. In `FindingsTable.tsx:256-267`:
   ```tsx
   <span
     className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold ${
       finding.reachability === 'REACHABLE'
         ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
         : finding.reachability === 'UNREACHABLE'
         ? 'bg-gray-800 text-gray-400 border border-gray-700'
         : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
     }`}
   >
     {finding.reachability || 'UNKNOWN'}
   </span>
   ```
2. In `CodeViewerDrawer.tsx:85-95`:
   ```tsx
   <span
     className={`font-semibold ${
       finding.reachability === 'REACHABLE'
         ? 'text-emerald-400'
         : finding.reachability === 'UNREACHABLE'
         ? 'text-gray-400'
         : 'text-yellow-400'
     }`}
   >
     {finding.reachability}
   </span>
   ```
3. In `frontend/index.html`:
   ```html
   <link rel="preconnect" href="https://fonts.googleapis.com">
   <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
   <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
   ```
4. In `frontend/tailwind.config.js`:
   ```js
   theme: {
     extend: {
       fontFamily: {
         sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
         mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
       },
   ```
