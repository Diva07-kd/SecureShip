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

  const engineCount = health?.scanners ? Object.keys(health.scanners).length : 5;

  return (
    <header className="border-b border-white/[0.08] bg-[#0d0e12]/80 backdrop-blur-xl sticky top-0 z-50 transition-all">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <Link to="/scan" className="flex items-center gap-3.5 group">
          {/* Antigravity Gradient Orb Icon */}
          <div className="relative w-9 h-9 rounded-xl bg-gradient-to-tr from-[#1a73e8] via-[#4285f4] to-[#a142f4] p-[1px] shadow-lg shadow-[#4285f4]/20 group-hover:shadow-[#4285f4]/35 transition-all duration-300">
            <div className="w-full h-full rounded-[11px] bg-[#0d0e12] flex items-center justify-center">
              <Shield className="w-4 h-4 text-[#8ab4f8] group-hover:scale-110 transition-transform" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base font-semibold text-white tracking-tight group-hover:text-[#8ab4f8] transition-colors">
                SecureScan
              </span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-[#4285f4]/10 text-[#8ab4f8] border border-[#4285f4]/25">
                AGENT-SEC
              </span>
            </div>
            <p className="text-[11px] text-[#9aa0a6] hidden sm:block">
              Defensive Application Security Platform &bull; Powered by SecureShip
            </p>
          </div>
        </Link>

        {/* Right Header Status & Navigation with Antigravity Pill Design */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.03] border border-white/[0.08] text-xs shadow-sm backdrop-blur-md hover:border-white/20 transition-colors">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#34a853] opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#34a853]"></span>
            </span>
            <span className="text-[#e8eaed] font-medium text-[11.5px]">{engineCount} Engines Active</span>
            <span className="text-[#9aa0a6] text-[10.5px] font-mono hidden md:inline border-l border-white/10 pl-2">
              SAST &bull; SCA &bull; Secrets &bull; IaC
            </span>
          </div>

          {isReportPage && (
            <Link
              to="/scan"
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full bg-white/[0.05] hover:bg-[#4285f4]/15 text-[#e8eaed] hover:text-[#8ab4f8] text-xs font-medium border border-white/[0.12] hover:border-[#4285f4]/40 transition-all duration-200 shadow-sm"
            >
              <RotateCcw className="w-3.5 h-3.5 text-[#8ab4f8]" />
              New Scan
            </Link>
          )}
        </div>
      </div>
    </header>
  );
};
