import React, { useEffect } from 'react';
import { X, FileCode, AlertCircle, Shield, ExternalLink, ChevronRight } from 'lucide-react';
import { NormalizedFinding } from '../types/report';

interface CodeViewerDrawerProps {
  finding: NormalizedFinding | null;
  onClose: () => void;
}

export const CodeViewerDrawer: React.FC<CodeViewerDrawerProps> = ({ finding, onClose }) => {
  // Close drawer on Escape key press
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!finding) return null;

  const loc = finding.location || { filePath: 'unknown', startLine: 1, endLine: 1 };
  const snippet = finding.snippetContext || finding.snippet;
  const lines = snippet?.lines || [];

  const pathParts = (loc.filePath || 'unknown').split(/[/\\]/);

  const getReachabilityTextClass = (verdict: string) => {
    switch (verdict) {
      case 'REACHABLE':
        return 'text-[#81c995]';
      case 'UNREACHABLE':
        return 'text-[#9aa0a6]';
      case 'UNKNOWN':
      default:
        return 'text-[#fbbc04]';
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Dimmed Antigravity backdrop */}
      <div
        className="absolute inset-0 bg-black/75 backdrop-blur-md transition-opacity"
        onClick={onClose}
      />

      <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
        <div className="w-screen max-w-2xl bg-[#131419] border-l border-white/[0.08] shadow-2xl flex flex-col">
          {/* Header */}
          <div className="p-5 border-b border-white/[0.08] flex items-start justify-between bg-[#0d0e12]/90 backdrop-blur-md">
            <div className="space-y-1.5 pr-4">
              <div className="flex items-center gap-2">
                <span
                  className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wide uppercase border ${finding.severity === 'CRITICAL'
                      ? 'bg-[#ea4335]/15 text-[#ea4335] border-[#ea4335]/30'
                      : finding.severity === 'HIGH'
                        ? 'bg-[#fa7b17]/15 text-[#fa7b17] border-[#fa7b17]/30'
                        : finding.severity === 'MEDIUM'
                          ? 'bg-[#fbbc04]/15 text-[#fbbc04] border-[#fbbc04]/30'
                          : finding.severity === 'LOW'
                            ? 'bg-[#4285f4]/15 text-[#8ab4f8] border-[#4285f4]/30'
                            : 'bg-white/[0.08] text-[#9aa0a6] border-white/15'
                    }`}
                >
                  {finding.severity}
                </span>
                <span className="text-xs font-mono text-[#9aa0a6]">{finding.scannerName}</span>
                <span className="text-xs text-[#5f6368]">&bull;</span>
                <span className="text-xs font-semibold text-[#c58af9]">{finding.category}</span>
              </div>
              <h3 className="text-base font-bold text-white tracking-tight">{finding.title}</h3>
              <p className="text-xs font-mono text-[#8ab4f8]">{finding.ruleId}</p>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-full text-[#9aa0a6] hover:text-white hover:bg-white/[0.08] transition"
              title="Close panel (Esc)"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Drawer Body */}
          <div className="flex-1 overflow-y-auto p-5 space-y-5">
            {/* Metadata Pills */}
            <div className="grid grid-cols-2 gap-3 p-4 rounded-xl bg-white/[0.02] border border-white/[0.08] text-xs">
              <div>
                <span className="text-[#9aa0a6] block text-[10px] uppercase font-semibold">Location</span>
                {/* Segmented Breadcrumb for File Path */}
                <div className="flex items-center flex-wrap gap-1 font-mono text-xs mt-0.5">
                  {pathParts.map((part, i) => (
                    <React.Fragment key={i}>
                      <span
                        className={
                          i === pathParts.length - 1
                            ? 'text-[#8ab4f8] font-semibold'
                            : 'text-[#9aa0a6]'
                        }
                      >
                        {part}
                      </span>
                      {i < pathParts.length - 1 && (
                        <ChevronRight className="w-3 h-3 text-[#5f6368] inline" />
                      )}
                    </React.Fragment>
                  ))}
                  <span className="text-[#5f6368]">:{loc.startLine}</span>
                </div>
              </div>
              <div>
                <span className="text-[#9aa0a6] block text-[10px] uppercase font-semibold">Reachability</span>
                <span className={`font-semibold ${getReachabilityTextClass(finding.reachability || 'UNKNOWN')}`}>
                  {finding.reachability || 'UNKNOWN'}
                </span>
              </div>
              <div>
                <span className="text-[#9aa0a6] block text-[10px] uppercase font-semibold">OWASP Category</span>
                <span className="text-[#e8eaed]">{finding.owaspCategory || 'None assigned'}</span>
              </div>
              <div>
                <span className="text-[#9aa0a6] block text-[10px] uppercase font-semibold">CWE Identifiers</span>
                <span className="font-mono text-[#8ab4f8]">
                  {finding.cweIds && finding.cweIds.length > 0 ? finding.cweIds.join(', ') : 'None'}
                </span>
              </div>
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <h4 className="text-xs font-semibold text-[#e8eaed] uppercase tracking-wider flex items-center gap-1.5">
                <AlertCircle className="w-3.5 h-3.5 text-[#8ab4f8]" />
                Vulnerability Details
              </h4>
              <p className="text-xs text-[#e8eaed] leading-relaxed bg-white/[0.02] p-3.5 rounded-xl border border-white/[0.08]">
                {finding.description || 'No detailed description available.'}
              </p>
            </div>

            {/* Code Snippet Box */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold text-[#e8eaed] uppercase tracking-wider flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-[#8ab4f8]" />
                  Code Context Window (&plusmn;5 lines)
                </h4>
                {snippet && (
                  <span className="text-[11px] font-mono text-[#9aa0a6]">
                    Lines {snippet.startLine} &ndash; {snippet.endLine}
                  </span>
                )}
              </div>

              {lines.length > 0 ? (
                <div className="rounded-xl border border-white/[0.08] bg-[#0d0e12] overflow-hidden font-mono text-xs">
                  {/* Segmented Breadcrumb in Snippet Header */}
                  <div className="px-3.5 py-2.5 bg-white/[0.03] border-b border-white/[0.08] text-[11px] text-[#9aa0a6] flex items-center justify-between">
                    <div className="flex items-center flex-wrap gap-1 font-mono">
                      {pathParts.map((part, i) => (
                        <React.Fragment key={i}>
                          <span
                            className={
                              i === pathParts.length - 1
                                ? 'text-[#8ab4f8] font-semibold'
                                : 'text-[#9aa0a6]'
                            }
                          >
                            {part}
                          </span>
                          {i < pathParts.length - 1 && (
                            <span className="text-[#5f6368]">/</span>
                          )}
                        </React.Fragment>
                      ))}
                    </div>
                    <span className="text-[10px] text-[#9aa0a6] font-mono">Target Line: {loc.startLine}</span>
                  </div>

                  <div className="overflow-x-auto py-2">
                    {lines.map((ln) => {
                      const isVulnerable = ln.isTarget;
                      return (
                        <div
                          key={ln.lineNumber}
                          className={`flex items-start px-3.5 py-0.5 leading-5 transition-colors ${isVulnerable
                              ? 'bg-[#ea4335]/15 text-[#fad2cf] border-l-4 border-[#ea4335] font-semibold'
                              : 'text-[#e8eaed] hover:bg-white/[0.02]'
                            }`}
                        >
                          <span
                            className={`w-12 select-none flex-shrink-0 text-right pr-4 ${isVulnerable ? 'text-[#ea4335] font-bold' : 'text-[#5f6368]'
                              }`}
                          >
                            {ln.lineNumber}
                          </span>
                          <span
                            className={`w-6 select-none flex-shrink-0 ${isVulnerable ? 'text-[#ea4335] font-bold' : 'text-[#5f6368]'
                              }`}
                          >
                            {isVulnerable ? '>>' : '  '}
                          </span>
                          <pre className="flex-1 whitespace-pre overflow-x-visible font-mono">{ln.content}</pre>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : snippet?.rawContent ? (
                <div className="rounded-xl border border-white/[0.08] bg-[#0d0e12] p-4 font-mono text-xs text-[#e8eaed] overflow-x-auto">
                  <pre>{snippet.rawContent}</pre>
                </div>
              ) : (
                <div className="rounded-xl border border-dashed border-white/[0.1] p-8 text-center text-xs text-[#5f6368]">
                  Source code snippet not available or file is external binary.
                </div>
              )}
            </div>

            {/* Hardened Remediation Guidance */}
            <div className="space-y-1.5 p-4 rounded-xl bg-[#4285f4]/10 border border-[#4285f4]/25 text-xs">
              <div className="flex items-center gap-1.5 font-semibold text-[#8ab4f8]">
                <Shield className="w-4 h-4 text-[#8ab4f8]" />
                Defensive Remediation Advice
              </div>
              <p className="text-[#e8eaed] text-xs mt-1 leading-relaxed">
                Refactor input handling to prevent untrusted inputs from reaching internal sinks. Consult OWASP cheat sheets
                and MITRE CWE guidance for authoritative defense patterns.
              </p>
              {finding.cweIds && finding.cweIds.length > 0 && (
                <div className="pt-2 flex flex-wrap gap-2">
                  {finding.cweIds.map((cwe) => {
                    const cweNum = cwe.replace(/\D/g, '');
                    return (
                      <a
                        key={cwe}
                        href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-[11px] text-[#8ab4f8] hover:text-[#aecbfa] underline font-mono"
                      >
                        {cwe} Reference
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
