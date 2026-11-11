import React, { useState } from 'react';
import { Download, FileJson, FileCode, Globe, FileText, Loader2 } from 'lucide-react';

interface ExportButtonsProps {
  jobId: string;
}

type ExportFormat = 'json' | 'sarif' | 'html' | 'pdf';

export const ExportButtons: React.FC<ExportButtonsProps> = ({ jobId }) => {
  const [downloadingFormat, setDownloadingFormat] = useState<ExportFormat | null>(null);

  const handleDownload = async (format: ExportFormat) => {
    setDownloadingFormat(format);
    try {
      const exportUrl = `/api/reports/${jobId}/export?format=${format}`;
      const response = await fetch(exportUrl);
      if (!response.ok) {
        throw new Error(`Export failed with HTTP ${response.status}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `securescan-${jobId}.${format === 'sarif' ? 'sarif' : format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Download error:', err);
      // Fallback: direct window location trigger
      window.open(`/api/reports/${jobId}/export?format=${format}`, '_blank');
    } finally {
      setDownloadingFormat(null);
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-[11px] font-semibold text-[#9aa0a6] uppercase tracking-wider mr-1 flex items-center gap-1.5">
        <Download className="w-3.5 h-3.5 text-[#8ab4f8]" />
        Export:
      </span>

      {/* JSON */}
      <button
        onClick={() => handleDownload('json')}
        disabled={downloadingFormat !== null}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-white/[0.04] hover:bg-white/[0.08] text-[#e8eaed] hover:text-white text-xs font-medium border border-white/[0.1] hover:border-white/[0.2] transition-all shadow-sm disabled:opacity-50 active:scale-95"
      >
        {downloadingFormat === 'json' ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin text-[#8ab4f8]" />
        ) : (
          <FileJson className="w-3.5 h-3.5 text-[#8ab4f8]" />
        )}
        JSON
      </button>

      {/* SARIF 2.1.0 */}
      <button
        onClick={() => handleDownload('sarif')}
        disabled={downloadingFormat !== null}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-white/[0.04] hover:bg-white/[0.08] text-[#e8eaed] hover:text-white text-xs font-medium border border-white/[0.1] hover:border-white/[0.2] transition-all shadow-sm disabled:opacity-50 active:scale-95"
      >
        {downloadingFormat === 'sarif' ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin text-[#c58af9]" />
        ) : (
          <FileCode className="w-3.5 h-3.5 text-[#c58af9]" />
        )}
        SARIF 2.1.0
      </button>

      {/* Standalone HTML */}
      <button
        onClick={() => handleDownload('html')}
        disabled={downloadingFormat !== null}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-white/[0.04] hover:bg-white/[0.08] text-[#e8eaed] hover:text-white text-xs font-medium border border-white/[0.1] hover:border-white/[0.2] transition-all shadow-sm disabled:opacity-50 active:scale-95"
      >
        {downloadingFormat === 'html' ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin text-[#81c995]" />
        ) : (
          <Globe className="w-3.5 h-3.5 text-[#81c995]" />
        )}
        Single-File HTML
      </button>

      {/* Binary Executive PDF */}
      <button
        onClick={() => handleDownload('pdf')}
        disabled={downloadingFormat !== null}
        className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full bg-gradient-to-r from-[#1a73e8] via-[#4285f4] to-[#a142f4] hover:shadow-[0_0_20px_rgba(66,133,244,0.4)] text-white text-xs font-semibold transition-all shadow-md active:scale-95 disabled:opacity-50"
      >
        {downloadingFormat === 'pdf' ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin text-white" />
        ) : (
          <FileText className="w-3.5 h-3.5 text-white" />
        )}
        Executive PDF
      </button>
    </div>
  );
};
