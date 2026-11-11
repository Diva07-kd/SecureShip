import React, { useState, useMemo } from 'react';
import { Search, Filter, Code2, ArrowUpDown, ChevronDown, X } from 'lucide-react';
import { NormalizedFinding, Severity } from '../types/report';

interface FindingsTableProps {
  findings: NormalizedFinding[];
  onSelectFinding: (finding: NormalizedFinding) => void;
  selectedOwasp?: string | null;
  onClearOwasp?: () => void;
  selectedOwaspFilter?: string | null;
  onClearOwaspFilter?: () => void;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

const SEVERITY_CLASSES: Record<Severity, { badge: string; text: string }> = {
  CRITICAL: {
    badge: 'bg-[#ea4335]/15 text-[#ea4335] border-[#ea4335]/30',
    text: 'text-[#ea4335]',
  },
  HIGH: {
    badge: 'bg-[#fa7b17]/15 text-[#fa7b17] border-[#fa7b17]/30',
    text: 'text-[#fa7b17]',
  },
  MEDIUM: {
    badge: 'bg-[#fbbc04]/15 text-[#fbbc04] border-[#fbbc04]/30',
    text: 'text-[#fbbc04]',
  },
  LOW: {
    badge: 'bg-[#4285f4]/15 text-[#8ab4f8] border-[#4285f4]/30',
    text: 'text-[#8ab4f8]',
  },
  INFO: {
    badge: 'bg-white/[0.08] text-[#9aa0a6] border-white/15',
    text: 'text-[#9aa0a6]',
  },
};

export const getReachabilityBadgeClass = (reachability: string) => {
  switch (reachability) {
    case 'REACHABLE':
      return 'bg-[#34a853]/15 text-[#81c995] border border-[#34a853]/30';
    case 'UNREACHABLE':
      return 'bg-white/[0.04] text-[#9aa0a6] border border-white/10';
    case 'UNKNOWN':
    default:
      return 'bg-[#fbbc04]/15 text-[#fbbc04] border border-[#fbbc04]/30';
  }
};

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onSelectFinding,
  selectedOwasp,
  onClearOwasp,
  selectedOwaspFilter,
  onClearOwaspFilter,
}) => {
  const activeOwasp = selectedOwasp ?? selectedOwaspFilter ?? null;
  const handleClearOwasp = () => {
    if (onClearOwasp) onClearOwasp();
    if (onClearOwaspFilter) onClearOwaspFilter();
  };

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedScanner, setSelectedScanner] = useState<string>('ALL');
  const [sortField, setSortField] = useState<'severity' | 'location' | 'rule'>('severity');
  const [sortAsc, setSortAsc] = useState(false);

  // Filter findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      // Search text match
      const q = searchQuery.toLowerCase().trim();
      const matchSearch =
        !q ||
        f.title?.toLowerCase().includes(q) ||
        f.ruleId?.toLowerCase().includes(q) ||
        f.location?.filePath?.toLowerCase().includes(q) ||
        f.description?.toLowerCase().includes(q) ||
        (f.cweIds && f.cweIds.some((cwe) => cwe.toLowerCase().includes(q)));

      // Severity match
      const matchSev = selectedSeverity === 'ALL' || f.severity === selectedSeverity;

      // Category match
      const matchCat = selectedCategory === 'ALL' || f.category === selectedCategory;

      // Scanner match
      const matchScanner = selectedScanner === 'ALL' || f.scannerName === selectedScanner;

      // OWASP match (if active from dashboard click)
      const matchOwasp = !activeOwasp || f.owaspCategory === activeOwasp;

      return matchSearch && matchSev && matchCat && matchScanner && matchOwasp;
    });
  }, [findings, searchQuery, selectedSeverity, selectedCategory, selectedScanner, activeOwasp]);

  // Sort findings
  const sortedFindings = useMemo(() => {
    return [...filteredFindings].sort((a, b) => {
      let comparison = 0;
      if (sortField === 'severity') {
        const rankA = SEVERITY_ORDER[a.severity] || 0;
        const rankB = SEVERITY_ORDER[b.severity] || 0;
        comparison = rankB - rankA; // Default highest first
      } else if (sortField === 'location') {
        const locA = a.location?.filePath || '';
        const locB = b.location?.filePath || '';
        comparison = locA.localeCompare(locB);
      } else if (sortField === 'rule') {
        const ruleA = a.ruleId || '';
        const ruleB = b.ruleId || '';
        comparison = ruleA.localeCompare(ruleB);
      }
      return sortAsc ? -comparison : comparison;
    });
  }, [filteredFindings, sortField, sortAsc]);

  const toggleSort = (field: 'severity' | 'location' | 'rule') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  return (
    <div className="agy-glass-card rounded-2xl overflow-hidden border border-white/[0.08] shadow-agy-card">
      {/* Table Controls / Filter Bar with Antigravity Capsule Selectors */}
      <div className="p-4 border-b border-white/[0.08] flex flex-wrap items-center justify-between gap-3 bg-white/[0.01]">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[260px]">
          <Search className="w-4 h-4 text-[#9aa0a6] absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by title, rule ID, CWE, or file path..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#18191f]/80 border border-white/[0.1] rounded-full pl-9 pr-4 py-2 text-xs text-[#e8eaed] placeholder-[#5f6368] focus:outline-none focus:border-[#4285f4] transition"
          />
        </div>

        {/* Dropdowns and Active OWASP Badge */}
        <div className="flex flex-wrap items-center gap-2">
          {activeOwasp && (
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-[#a142f4]/15 text-[#c58af9] border border-[#a142f4]/30 text-xs font-medium">
              <span>OWASP: {activeOwasp}</span>
              <button
                onClick={handleClearOwasp}
                className="p-0.5 rounded-full hover:bg-[#a142f4]/30 text-[#c58af9] hover:text-white transition"
                title="Clear OWASP filter"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          {/* Severity Dropdown */}
          <div className="relative">
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="appearance-none bg-[#18191f]/80 border border-white/[0.1] rounded-full pl-3.5 pr-8 py-2 text-xs font-medium text-[#e8eaed] focus:outline-none focus:border-[#4285f4] cursor-pointer hover:border-white/20 transition"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-[#9aa0a6] absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>

          {/* Category Dropdown */}
          <div className="relative">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="appearance-none bg-[#18191f]/80 border border-white/[0.1] rounded-full pl-3.5 pr-8 py-2 text-xs font-medium text-[#e8eaed] focus:outline-none focus:border-[#4285f4] cursor-pointer hover:border-white/20 transition"
            >
              <option value="ALL">All Categories</option>
              <option value="SAST">SAST</option>
              <option value="SCA">SCA</option>
              <option value="SECRET">Secret</option>
              <option value="IAC">IaC</option>
              <option value="SUPPLY_CHAIN">Supply Chain</option>
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-[#9aa0a6] absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>

          {/* Scanner Dropdown */}
          <div className="relative">
            <select
              value={selectedScanner}
              onChange={(e) => setSelectedScanner(e.target.value)}
              className="appearance-none bg-[#18191f]/80 border border-white/[0.1] rounded-full pl-3.5 pr-8 py-2 text-xs font-medium text-[#e8eaed] focus:outline-none focus:border-[#4285f4] cursor-pointer hover:border-white/20 transition"
            >
              <option value="ALL">All Scanners</option>
              <option value="opengrep">opengrep</option>
              <option value="gitleaks">gitleaks</option>
              <option value="trivy">trivy</option>
              <option value="osv-scanner">osv-scanner</option>
              <option value="checkov">checkov</option>
            </select>
            <ChevronDown className="w-3.5 h-3.5 text-[#9aa0a6] absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-white/[0.08] text-[11px] font-semibold text-[#9aa0a6] uppercase tracking-wider bg-white/[0.02]">
              <th className="py-3 px-4 cursor-pointer hover:text-white transition-colors" onClick={() => toggleSort('severity')}>
                <div className="flex items-center gap-1.5">
                  Severity
                  <ArrowUpDown className="w-3 h-3 text-[#5f6368]" />
                </div>
              </th>
              <th className="py-3 px-4 cursor-pointer hover:text-white transition-colors" onClick={() => toggleSort('rule')}>
                <div className="flex items-center gap-1.5">
                  Vulnerability & Rule
                  <ArrowUpDown className="w-3 h-3 text-[#5f6368]" />
                </div>
              </th>
              <th className="py-3 px-4">Scanner</th>
              <th className="py-3 px-4">OWASP Top 10</th>
              <th className="py-3 px-4">Reachability</th>
              <th className="py-3 px-4 cursor-pointer hover:text-white transition-colors" onClick={() => toggleSort('location')}>
                <div className="flex items-center gap-1.5">
                  Location
                  <ArrowUpDown className="w-3 h-3 text-[#5f6368]" />
                </div>
              </th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.05] text-xs">
            {sortedFindings.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-[#9aa0a6]">
                  <Filter className="w-8 h-8 mx-auto text-[#5f6368] mb-2" />
                  No findings matching current search or filters.
                </td>
              </tr>
            ) : (
              sortedFindings.map((finding) => {
                const sevInfo = SEVERITY_CLASSES[finding.severity] || SEVERITY_CLASSES.INFO;
                const loc = finding.location || { filePath: 'unknown', startLine: 1 };
                const cwes = finding.cweIds && finding.cweIds.length > 0 ? finding.cweIds.join(', ') : null;

                return (
                  <tr
                    key={finding.id}
                    className="hover:bg-white/[0.03] transition-colors group cursor-pointer"
                    onClick={() => onSelectFinding(finding)}
                  >
                    {/* Severity Badge */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold border tracking-wide uppercase ${sevInfo.badge}`}>
                        {finding.severity}
                      </span>
                    </td>

                    {/* Title & Rule */}
                    <td className="py-3.5 px-4 max-w-xs sm:max-w-md">
                      <div className="font-semibold text-white tracking-tight truncate group-hover:text-[#8ab4f8] transition-colors">
                        {finding.title}
                      </div>
                      <div className="text-[11px] font-mono text-[#9aa0a6] mt-0.5 truncate">
                        {finding.ruleId}
                        {cwes && <span className="ml-2 text-[#8ab4f8] font-sans">({cwes})</span>}
                      </div>
                    </td>

                    {/* Scanner */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded-full bg-white/[0.04] border border-white/[0.1] text-[#e8eaed] font-mono text-[10px]">
                        {finding.scannerName}
                      </span>
                    </td>

                    {/* OWASP Category */}
                    <td className="py-3.5 px-4 whitespace-nowrap text-[#9aa0a6] text-[11px]">
                      {finding.owaspCategory || 'Unknown'}
                    </td>

                    {/* Reachability Verdict */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-semibold border ${getReachabilityBadgeClass(
                          finding.reachability || 'UNKNOWN'
                        )}`}
                      >
                        {finding.reachability || 'UNKNOWN'}
                      </span>
                    </td>

                    {/* File Location */}
                    <td className="py-3.5 px-4 font-mono text-[#9aa0a6] text-[11px] max-w-[200px] truncate">
                      {loc.filePath}:{loc.startLine}
                    </td>

                    {/* Inspect Button */}
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFinding(finding);
                        }}
                        className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#4285f4]/10 hover:bg-[#4285f4]/25 text-[#8ab4f8] text-xs font-medium border border-[#4285f4]/30 hover:border-[#4285f4]/50 transition shadow-sm active:scale-95"
                      >
                        <Code2 className="w-3.5 h-3.5" />
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Findings Count Footer */}
      <div className="p-3.5 border-t border-white/[0.08] bg-white/[0.01] text-xs text-[#9aa0a6] flex items-center justify-between">
        <div>
          Showing <span className="font-semibold text-white">{sortedFindings.length}</span> of{' '}
          <span className="font-semibold text-white">{findings.length}</span> findings
        </div>
        <div className="text-[11px] font-mono text-[#5f6368]">Click any row to open the context-pinned code drawer</div>
      </div>
    </div>
  );
};
