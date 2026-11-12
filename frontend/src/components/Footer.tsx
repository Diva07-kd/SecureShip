import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-white/[0.08] py-8 text-center text-xs text-[#69746b] mt-auto bg-[#f6f6f1]/60 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-[#557b37]"></div>
          <span className="font-medium text-[#252d27]">SecureScan</span>
          <span className="text-[#7c877e]">&bull;</span>
          <span>Defensive Security Platform</span>
          <span className="text-[#7c877e]">&bull;</span>
          <span className="text-[#557b37]">Heyram Infrastructure Assessment</span>
        </div>
        <div className="flex items-center gap-2 text-[11px] font-mono text-[#69746b]">
          <span>MITRE CWE</span>
          <span className="text-[#7c877e]">&bull;</span>
          <span>OWASP Top 10 (2021)</span>
          <span className="text-[#7c877e]">&bull;</span>
          <span>OASIS SARIF 2.1.0</span>
        </div>
      </div>
    </footer>
  );
};
