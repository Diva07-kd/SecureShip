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
      stage: 'extracting',
      progress: 10,
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
    <div className="space-y-12 py-6">
      {/* State 1: Upload View */}
      {!activeJobId && (
        <div className="space-y-10">
          <div className="text-center max-w-3xl mx-auto space-y-4">
            {/* Antigravity Announcement Pill */}
            <div className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-white/[0.04] border border-white/[0.12] text-xs shadow-sm hover:border-[#557b37]/40 transition-all cursor-default">
              <span className="px-2 py-0.5 rounded-full text-[9.5px] font-bold uppercase tracking-wider bg-gradient-to-r from-[#405f2b] to-[#557b37] text-white shadow-sm">
                DEFENSIVE APPSEC
              </span>
              <span className="text-[#252d27] text-xs font-medium">Built for the Agent-First Era</span>
              <span className="text-[#7c877e]">&bull;</span>
              <span className="text-[#557b37] text-[11px] font-mono">5 Engines Pre-baked</span>
            </div>

            <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-white agy-gradient-text leading-tight">
              Multi-Engine Defensive Security Scanner
            </h1>
            <p className="text-sm sm:text-base text-[#69746b] max-w-2xl mx-auto leading-relaxed">
              Upload your source code or application zip archive to execute automated SAST, SCA, Secret Detection,
              and IaC security audits with reachability verification and code snippet context.
            </p>
          </div>

          <UploadZone onUploadSuccess={handleUploadSuccess} />
        </div>
      )}

      {/* State 2: Scanning & Progress Polling View with Antigravity Orbital Animation */}
      {activeJobId && jobStatus && jobStatus.status !== 'done' && jobStatus.status !== 'failed' && (
        <div className="max-w-2xl mx-auto py-16 text-center space-y-8 agy-glass-card rounded-2xl p-8 border border-white/[0.1]">
          {/* Orbital Dual Rings */}
          <div className="relative w-28 h-28 mx-auto flex items-center justify-center">
            <div className="absolute inset-0 rounded-full border-2 border-white/[0.08]" />
            <div className="absolute inset-0 rounded-full border-2 border-[#557b37]/20 border-t-[#557b37] animate-spin" />
            <div className="absolute inset-3 rounded-full border-2 border-[#82956f]/20 border-b-[#82956f] animate-spin [animation-duration:1.5s] [animation-direction:reverse]" />
            <Shield className="w-9 h-9 text-[#557b37] animate-pulse" />
          </div>

          <div className="space-y-2">
            <h3 className="text-2xl font-bold text-white tracking-tight">Security Scan in Progress</h3>
            <p className="text-xs text-[#69746b] font-mono">
              Target: <span className="text-[#252d27] font-semibold">{scanTargetName}</span> &bull; Job ID: {activeJobId}
            </p>
          </div>

          {/* Stage Indicator Pills */}
          <div className="grid grid-cols-3 gap-2.5 max-w-lg mx-auto text-xs font-medium">
            <div
              className={`p-3 rounded-xl border transition-all ${jobStatus.stage === 'extracting' || jobStatus.stage === 'queued'
                  ? 'bg-[#557b37]/15 border-[#557b37]/40 text-[#557b37] shadow-sm shadow-[#557b37]/10'
                  : 'bg-white/[0.02] border-white/[0.06] text-[#7c877e]'
                }`}
            >
              1. Safe Extract
            </div>
            <div
              className={`p-3 rounded-xl border transition-all ${jobStatus.stage === 'scanning'
                  ? 'bg-[#557b37]/15 border-[#557b37]/40 text-[#557b37] shadow-sm shadow-[#557b37]/10'
                  : 'bg-white/[0.02] border-white/[0.06] text-[#7c877e]'
                }`}
            >
              2. Engine Scan
            </div>
            <div
              className={`p-3 rounded-xl border transition-all ${jobStatus.stage === 'enriching'
                  ? 'bg-[#557b37]/15 border-[#557b37]/40 text-[#557b37] shadow-sm shadow-[#557b37]/10'
                  : 'bg-white/[0.02] border-white/[0.06] text-[#7c877e]'
                }`}
            >
              3. Snippets & OWASP
            </div>
          </div>

          {/* Animated Progress Bar */}
          <div className="w-full max-w-md mx-auto space-y-2">
            <div className="h-2 w-full bg-white/[0.05] rounded-full overflow-hidden border border-white/[0.08]">
              <div
                className="h-full bg-gradient-to-r from-[#557b37] via-[#82956f] to-[#b4c2a6] transition-all duration-500 rounded-full"
                style={{ width: `${Math.max(jobStatus.progress || 10, 15)}%` }}
              />
            </div>
            <div className="flex justify-between text-[11px] font-mono text-[#69746b]">
              <span>Polling engine status every 2s</span>
              <span className="text-[#252d27] font-semibold">{jobStatus.progress || 10}%</span>
            </div>
          </div>
        </div>
      )}

      {/* State 3: Scan Failed View */}
      {jobStatus && jobStatus.status === 'failed' && (
        <div className="max-w-xl mx-auto py-12 text-center space-y-4 agy-glass-card rounded-2xl p-8 border border-[#ea4335]/30">
          <div className="w-16 h-16 rounded-full bg-[#ea4335]/10 border border-[#ea4335]/30 flex items-center justify-center mx-auto text-[#ea4335]">
            <AlertTriangle className="w-8 h-8" />
          </div>
          <h3 className="text-xl font-bold text-white">Scan Execution Rejected</h3>
          <div className="p-4 rounded-xl bg-[#ea4335]/10 border border-[#ea4335]/20 text-[#a63a2f] text-xs text-left font-mono">
            {jobStatus.error || 'Scan process encountered an unhandled execution error.'}
          </div>
          <button
            onClick={handleReset}
            className="inline-flex items-center gap-1.5 px-6 py-2.5 rounded-full bg-gradient-to-r from-[#405f2b] to-[#557b37] hover:shadow-[0_0_20px_rgba(85,123,55,0.22)] text-white text-xs font-semibold transition-all shadow-md"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Analyze Another Archive
          </button>
        </div>
      )}
    </div>
  );
};
