import React, { useMemo } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { ShieldCheck, AlertTriangle, Cpu, Clock, FileText } from 'lucide-react';
import { ScanReport } from '../types/report';

interface SummaryDashboardProps {
  report: ScanReport;
  onFilterOwasp?: (cat: string) => void;
  selectedOwasp?: string | null;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ea4335', // Google Red
  HIGH: '#fa7b17',     // Google Orange
  MEDIUM: '#d29b2e',   // Google Yellow
  LOW: '#557b37',      // Google Blue
  INFO: '#69746b',     // Google Gray
};

export const SummaryDashboard: React.FC<SummaryDashboardProps> = ({
  report,
  onFilterOwasp,
  selectedOwasp,
}) => {
  const summary = report.summary || {
    totalFindings: 0,
    bySeverity: {},
    byOwasp: {},
    byScanner: {},
    byCategory: {},
  };

  const bySev = summary.bySeverity || summary.severityCounts || {};
  const totalFindings = report.summary?.totalFindings ?? report.findings?.length ?? 0;
  const critCount = bySev.CRITICAL || 0;
  const highCount = bySev.HIGH || 0;
  const medCount = bySev.MEDIUM || 0;
  const lowCount = bySev.LOW || 0;
  const infoCount = bySev.INFO || 0;

  // Pie chart data
  const severityData = [
    { name: 'CRITICAL', value: critCount, color: SEVERITY_COLORS.CRITICAL },
    { name: 'HIGH', value: highCount, color: SEVERITY_COLORS.HIGH },
    { name: 'MEDIUM', value: medCount, color: SEVERITY_COLORS.MEDIUM },
    { name: 'LOW', value: lowCount, color: SEVERITY_COLORS.LOW },
    { name: 'INFO', value: infoCount, color: SEVERITY_COLORS.INFO },
  ].filter((item) => item.value > 0);

  // Files affected calculation
  const filesAffected = useMemo(() => {
    if (!report.findings || report.findings.length === 0) return 0;
    const unique = new Set(report.findings.map((f) => f.location?.filePath).filter(Boolean));
    return unique.size;
  }, [report.findings]);

  // Scanners run calculation
  const scannersRun =
    report.scanners?.length || Object.keys(report.summary?.byScanner || {}).length || 5;

  // Scan duration calculation
  const durationSec = ((report.durationMs || 0) / 1000).toFixed(1) + 's';

  // Scanner breakdown data
  const scannerCounts: Record<string, number> = {};
  if (summary.byScanner && Object.keys(summary.byScanner).length > 0) {
    Object.entries(summary.byScanner).forEach(([k, v]) => {
      scannerCounts[k] = v;
    });
  } else if (report.findings) {
    report.findings.forEach((f) => {
      const s = f.scannerName || 'generic';
      scannerCounts[s] = (scannerCounts[s] || 0) + 1;
    });
  }
  // Ensure common engines exist in breakdown
  ['opengrep', 'gitleaks', 'trivy', 'osv-scanner', 'checkov'].forEach((name) => {
    if (scannerCounts[name] === undefined) {
      scannerCounts[name] = 0;
    }
  });

  const scannerData = Object.entries(scannerCounts).map(([name, count]) => ({
    name,
    count,
  }));

  // OWASP breakdown data
  const owaspCounts = summary.byOwasp || summary.owaspCounts || {};
  const owaspData = Object.entries(owaspCounts)
    .filter(([_, count]) => count > 0)
    .map(([category, count]) => {
      // Shorten label for chart e.g. "A03:2021-Injection" -> "A03 Injection"
      const short = category.replace(':2021', '').substring(0, 18);
      return {
        fullName: category,
        name: short,
        count,
      };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 7);

  return (
    <div className="space-y-6">
      {/* Top 4 Stat Cards with Antigravity Glassmorphism */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Findings */}
        <div className="agy-glass-card rounded-2xl p-5 relative overflow-hidden border border-white/[0.08] shadow-agy-card">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#69746b]">
              Total Findings
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#ea4335]/15 border border-[#ea4335]/30 flex items-center justify-center text-[#ea4335]">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white tracking-tight">{totalFindings}</span>
            <span className="text-xs text-[#69746b]">across codebase</span>
          </div>
          <div className="mt-3 text-xs text-[#69746b] flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-[#ea4335]"></span>
            Multi-engine consolidated
          </div>
        </div>

        {/* Card 2: Files Affected */}
        <div className="agy-glass-card rounded-2xl p-5 relative overflow-hidden border border-white/[0.08] shadow-agy-card">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#69746b]">
              Files Affected
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#557b37]/15 border border-[#557b37]/30 flex items-center justify-center text-[#557b37]">
              <FileText className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white tracking-tight">{filesAffected}</span>
            <span className="text-xs text-[#69746b]">unique target files</span>
          </div>
          <div className="mt-3 text-xs text-[#69746b] flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-[#557b37]"></span>
            Vulnerable source surfaces
          </div>
        </div>

        {/* Card 3: Scanners Run */}
        <div className="agy-glass-card rounded-2xl p-5 relative overflow-hidden border border-white/[0.08] shadow-agy-card">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#69746b]">
              Scanners Run
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#718c4f]/15 border border-[#718c4f]/30 flex items-center justify-center text-[#536f3f]">
              <Cpu className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white tracking-tight">{scannersRun}</span>
            <span className="text-xs text-[#69746b]">SAST &bull; SCA &bull; Secrets &bull; IaC</span>
          </div>
          <div className="mt-3 text-xs text-[#536f3f] flex items-center gap-1.5 font-medium">
            <ShieldCheck className="w-3.5 h-3.5" />
            100% Pre-baked in container
          </div>
        </div>

        {/* Card 4: Scan Duration */}
        <div className="agy-glass-card rounded-2xl p-5 relative overflow-hidden border border-white/[0.08] shadow-agy-card">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[#69746b]">
              Scan Duration
            </span>
            <div className="w-8 h-8 rounded-lg bg-[#b4c2a6]/15 border border-[#b4c2a6]/30 flex items-center justify-center text-[#b4c2a6]">
              <Clock className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white tracking-tight">{durationSec}</span>
            <span className="text-xs text-[#69746b]">execution time</span>
          </div>
          <div className="mt-3 text-xs text-[#69746b] flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-[#b4c2a6]"></span>
            Asynchronous single-queue
          </div>
        </div>
      </div>

      {/* Visual Analytics Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Donut Chart */}
        <div className="agy-glass-card rounded-2xl p-6 border border-white/[0.08] flex flex-col items-center">
          <h4 className="text-sm font-semibold text-white tracking-tight self-start mb-2">Severity Breakdown</h4>
          {severityData.length === 0 ? (
            <div className="h-56 flex flex-col items-center justify-center text-[#69746b] text-sm">
              <ShieldCheck className="w-12 h-12 text-[#718c4f] mb-2" />
              Clean Scan &bull; Zero Findings
            </div>
          ) : (
            <div className="w-full h-56 relative flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="#f6f6f1" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: 'rgba(37,45,39,0.12)', borderRadius: '12px', boxShadow: '0 8px 24px rgba(31,43,35,0.12)' }}
                    itemStyle={{ color: '#252d27' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-2xl font-bold text-white tracking-tight">{totalFindings}</span>
                <span className="text-[10px] uppercase tracking-wider text-[#69746b]">Total</span>
              </div>
            </div>
          )}

          <div className="flex flex-wrap justify-center gap-3 mt-3 text-xs">
            {Object.entries(SEVERITY_COLORS).map(([sev, color]) => (
              <div key={sev} className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: color }}></span>
                <span className="text-[#69746b]">{sev}:</span>
                <span className="font-semibold text-white">{bySev[sev] || 0}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Engine Breakdown Bar Chart */}
        <div className="agy-glass-card rounded-2xl p-6 border border-white/[0.08] flex flex-col">
          <h4 className="text-sm font-semibold text-white tracking-tight mb-2">Findings by Scanner Engine</h4>
          <div className="w-full h-56 mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scannerData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                <XAxis dataKey="name" stroke="#69746b" fontSize={11} angle={-25} textAnchor="end" />
                <YAxis stroke="#69746b" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', borderColor: 'rgba(37,45,39,0.12)', borderRadius: '12px', boxShadow: '0 8px 24px rgba(31,43,35,0.12)' }}
                  itemStyle={{ color: '#252d27' }}
                />
                <Bar dataKey="count" fill="#557b37" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="text-[11px] text-[#69746b] text-center mt-auto font-mono">
            Parallel multi-scanner coverage with deduplication
          </div>
        </div>

        {/* OWASP Top 10 Breakdown Bar Chart */}
        <div className="agy-glass-card rounded-2xl p-6 border border-white/[0.08] flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-semibold text-white tracking-tight">OWASP Top 10 (2021) Distribution</h4>
            {selectedOwasp && (
              <span className="text-[10.5px] text-[#62794a] font-medium bg-[#82956f]/15 px-2 py-0.5 rounded-full border border-[#82956f]/30">
                Filtered
              </span>
            )}
          </div>
          {owaspData.length === 0 ? (
            <div className="h-56 flex flex-col items-center justify-center text-[#69746b] text-sm">
              <ShieldCheck className="w-10 h-10 text-[#718c4f] mb-2" />
              No OWASP Violations
            </div>
          ) : (
            <div className="w-full h-56 mt-2">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={owaspData}
                  layout="vertical"
                  margin={{ top: 5, right: 20, left: 20, bottom: 5 }}
                >
                  <XAxis type="number" stroke="#69746b" fontSize={11} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" stroke="#69746b" fontSize={10} width={90} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#ffffff', borderColor: 'rgba(37,45,39,0.12)', borderRadius: '12px', boxShadow: '0 8px 24px rgba(31,43,35,0.12)' }}
                    itemStyle={{ color: '#252d27' }}
                    formatter={(_val: any, _name: any, item: any) => [item.payload.count, item.payload.fullName]}
                  />
                  <Bar
                    dataKey="count"
                    radius={[0, 6, 6, 0]}
                    className="cursor-pointer"
                    onClick={(entry: any) => {
                      if (entry && onFilterOwasp) {
                        const cat = entry.fullName || entry.name;
                        if (cat) onFilterOwasp(cat);
                      }
                    }}
                  >
                    {owaspData.map((entry, index) => (
                      <Cell
                        key={`cell-owasp-${index}`}
                        fill={selectedOwasp === entry.fullName ? '#62794a' : '#82956f'}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
          <div className="text-[11px] text-[#69746b] text-center mt-auto font-mono">
            Click any bar to filter findings by OWASP category
          </div>
        </div>
      </div>
    </div>
  );
};
