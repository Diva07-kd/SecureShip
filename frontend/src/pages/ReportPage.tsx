import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  FileArchive,
  Layers,
  AlertTriangle,
  RotateCcw,
  Shield,
  Loader2,
  Calendar,
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
  const [selectedOwasp, setSelectedOwasp] = useState<string | null>(null);

  useEffect(() => {
    if (!effectiveJobId) {
      setErrorMessage('No Job ID specified.');
      setIsLoading(false);
      return;
    }

    let isMounted = true;
    let pollInterval: ReturnType<typeof setInterval> | null = null;

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

        // If report is not yet ready (404/409/422), check job status
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

          // Job is queued or running
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
    // Poll every 2 seconds until done or failed
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
        <Loader2 className="w-10 h-10 animate-spin text-[#8ab4f8] mx-auto" />
        <p className="text-sm text-[#9aa0a6]">Loading scan report for job <span className="font-mono text-[#e8eaed]">{effectiveJobId}</span>...</p>
      </div>
    );
  }

  // Error State: Report Not Found or Failed
  if (errorMessage) {
    return (
      <div className="max-w-xl mx-auto py-16 text-center space-y-5 agy-glass-card rounded-2xl p-8 border border-[#ea4335]/30">
        <div className="w-16 h-16 rounded-full bg-[#ea4335]/10 border border-[#ea4335]/30 flex items-center justify-center mx-auto text-[#ea4335]">
          <AlertTriangle className="w-8 h-8" />
        </div>
        <h3 className="text-xl font-bold text-white">Report Not Found</h3>
        <div className="p-4 rounded-xl bg-[#ea4335]/10 border border-[#ea4335]/20 text-[#fad2cf] text-xs text-left font-mono">
          {errorMessage}
        </div>
        <Link
          to="/scan"
          className="inline-flex items-center gap-1.5 px-6 py-2.5 rounded-full bg-gradient-to-r from-[#1a73e8] to-[#4285f4] hover:shadow-[0_0_20px_rgba(66,133,244,0.4)] text-white text-xs font-semibold transition-all shadow-md"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          Start New Scan
        </Link>
      </div>
    );
  }

  // Scan in progress view (e.g. direct link accessed while job still running)
  if (!report && jobStatus && (jobStatus.status === 'queued' || jobStatus.status === 'running')) {
    return (
      <div className="max-w-2xl mx-auto py-16 text-center space-y-8 agy-glass-card rounded-2xl p-8 border border-white/[0.1]">
        <div className="relative w-28 h-28 mx-auto flex items-center justify-center">
          <div className="absolute inset-0 rounded-full border-2 border-white/[0.08]" />
          <div className="absolute inset-0 rounded-full border-2 border-[#4285f4]/20 border-t-[#4285f4] animate-spin" />
          <div className="absolute inset-3 rounded-full border-2 border-[#a142f4]/20 border-b-[#a142f4] animate-spin [animation-duration:1.5s] [animation-direction:reverse]" />
          <Shield className="w-9 h-9 text-[#8ab4f8] animate-pulse" />
        </div>

        <div className="space-y-2">
          <h3 className="text-2xl font-bold text-white tracking-tight">Security Scan in Progress</h3>
          <p className="text-xs text-[#9aa0a6] font-mono">
            Target: <span className="text-[#e8eaed]">{jobStatus.targetName || 'Codebase'}</span> &bull; Job ID: {effectiveJobId}
          </p>
        </div>

        {/* Animated Progress Bar */}
        <div className="w-full max-w-md mx-auto space-y-2">
          <div className="h-2 w-full bg-white/[0.05] rounded-full overflow-hidden border border-white/[0.08]">
            <div
              className="h-full bg-gradient-to-r from-[#4285f4] via-[#a142f4] to-[#24c1e0] transition-all duration-500 rounded-full"
              style={{ width: `${Math.max(jobStatus.progress || 10, 15)}%` }}
            />
          </div>
          <div className="flex justify-between text-[11px] font-mono text-[#9aa0a6]">
            <span>Stage: {jobStatus.stage || 'scanning'} &bull; Polling every 2s</span>
            <span className="text-[#e8eaed] font-semibold">{jobStatus.progress || 10}%</span>
          </div>
        </div>
      </div>
    );
  }

  if (!report) return null;

  const totalFindingsCount = report.summary?.totalFindings ?? report.findings?.length ?? 0;
  const scanDate = report.createdAt ? new Date(report.createdAt).toLocaleString() : '';

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header bar: target name, scan timestamp, job ID, total findings badge with Antigravity styling */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-5 p-6 rounded-2xl agy-glass border border-white/[0.08] shadow-agy-card">
        <div className="space-y-2">
          <div className="flex items-center flex-wrap gap-3">
            <div className="w-9 h-9 rounded-xl bg-[#4285f4]/10 border border-[#4285f4]/20 flex items-center justify-center text-[#8ab4f8] shadow-inner">
              <FileArchive className="w-4 h-4" />
            </div>
            <span className="font-bold text-white text-xl tracking-tight">
              {report.targetName || 'Target Codebase'}
            </span>
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-[#34a853]/15 text-[#81c995] border border-[#34a853]/30">
              SCAN COMPLETE
            </span>
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-[#4285f4]/15 text-[#8ab4f8] border border-[#4285f4]/30">
              {totalFindingsCount} {totalFindingsCount === 1 ? 'Finding' : 'Findings'}
            </span>
          </div>
          <div className="flex items-center flex-wrap gap-4 text-xs text-[#9aa0a6] font-mono">
            <span>Job ID: {effectiveJobId || report.id}</span>
            {scanDate && (
              <span className="flex items-center gap-1.5 text-[#9aa0a6]">
                <Calendar className="w-3.5 h-3.5 text-[#5f6368]" />
                {scanDate}
              </span>
            )}
          </div>
        </div>

        {/* Multi-Format Export Bar */}
        <ExportButtons jobId={effectiveJobId || report.id} />
      </div>

      {/* Summary Statistics & Charts with OWASP click-to-filter callback */}
      <SummaryDashboard
        report={report}
        onFilterOwasp={(cat) => setSelectedOwasp(cat === selectedOwasp ? null : cat)}
        selectedOwasp={selectedOwasp}
      />

      {/* Filterable Findings Table */}
      <div className="space-y-3 pt-2">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-bold text-white flex items-center gap-2 tracking-tight">
            <Layers className="w-4 h-4 text-[#8ab4f8]" />
            Security Audit Findings
          </h3>
        </div>

        <FindingsTable
          findings={report.findings || []}
          onSelectFinding={(f) => setSelectedFinding(f)}
          selectedOwasp={selectedOwasp}
          onClearOwasp={() => setSelectedOwasp(null)}
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
