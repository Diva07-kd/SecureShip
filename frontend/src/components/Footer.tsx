import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-white/[0.08] py-8 text-center text-xs text-[#9aa0a6] mt-auto bg-[#0d0e12]/60 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-[#4285f4]"></div>
          <span className="font-medium text-[#e8eaed]">SecureScan</span>
          <span className="text-[#5f6368]">&bull;</span>
          <span>Defensive Security Platform</span>
          <span className="text-[#5f6368]">&bull;</span>
          <span className="text-[#8ab4f8]">Heyram Infrastructure Assessment</span>
        </div>
        <div className="flex items-center gap-2 text-[11px] font-mono text-[#9aa0a6]">
          <span>MITRE CWE</span>
          <span className="text-[#5f6368]">&bull;</span>
          <span>OWASP Top 10 (2021)</span>
          <span className="text-[#5f6368]">&bull;</span>
          <span>OASIS SARIF 2.1.0</span>
        </div>
      </div>
    </footer>
  );
};
