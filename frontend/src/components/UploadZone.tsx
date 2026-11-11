import React, { useState, useRef } from 'react';
import { UploadCloud, FileArchive, AlertCircle, ShieldAlert } from 'lucide-react';

interface UploadZoneProps {
  onUploadSuccess: (jobId: string, filename: string) => void;
}

const MAX_SIZE_BYTES = 600 * 1024 * 1024; // 600 MB

export const UploadZone: React.FC<UploadZoneProps> = ({ onUploadSuccess }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateAndUpload = async (file: File) => {
    setErrorMessage(null);

    // Enforce .zip extension
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setErrorMessage(`Invalid archive "${file.name}". SecureScan exclusively accepts .zip archives.`);
      return;
    }

    // Enforce 600 MB client-side ceiling
    if (file.size > MAX_SIZE_BYTES) {
      const sizeMb = (file.size / (1024 * 1024)).toFixed(1);
      setErrorMessage(`Archive exceeds 600 MB size limit (selected file is ${sizeMb} MB).`);
      return;
    }

    setIsUploading(true);
    setUploadProgress(10);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/scan');

      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) {
          const percent = Math.round((event.loaded / event.total) * 90);
          setUploadProgress(percent);
        }
      };

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          setUploadProgress(100);
          const response = JSON.parse(xhr.responseText);
          onUploadSuccess(response.job_id, file.name);
        } else {
          try {
            const err = JSON.parse(xhr.responseText);
            setErrorMessage(err.detail || 'Upload failed due to server error.');
          } catch {
            setErrorMessage(`Upload failed with HTTP ${xhr.status}`);
          }
          setIsUploading(false);
        }
      };

      xhr.onerror = () => {
        setErrorMessage('Network error during file upload. Please verify backend server is reachable.');
        setIsUploading(false);
      };

      xhr.send(formData);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown upload error occurred';
      setErrorMessage(msg);
      setIsUploading(false);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndUpload(e.target.files[0]);
    }
  };

  return (
    <div className="w-full max-w-3xl mx-auto space-y-6">
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !isUploading && fileInputRef.current?.click()}
        className={`relative rounded-2xl p-12 text-center transition-all duration-300 cursor-pointer select-none border ${isDragging
            ? 'border-[#4285f4] bg-[#4285f4]/10 shadow-[0_0_40px_rgba(66,133,244,0.25)] scale-[1.01]'
            : 'border-white/[0.1] bg-white/[0.02] hover:border-white/[0.2] hover:bg-white/[0.04] shadow-agy-card'
          } ${isUploading ? 'pointer-events-none opacity-85' : ''}`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".zip,application/zip,application/x-zip-compressed"
          onChange={handleFileChange}
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center space-y-5">
          {/* Antigravity Upload Icon Squircle */}
          <div className="relative w-16 h-16 rounded-2xl bg-gradient-to-br from-[#4285f4]/20 via-[#a142f4]/15 to-transparent border border-white/[0.12] flex items-center justify-center text-[#8ab4f8] shadow-inner">
            {isUploading ? (
              <FileArchive className="w-7 h-7 animate-pulse text-[#8ab4f8]" />
            ) : (
              <UploadCloud className="w-7 h-7 text-[#8ab4f8]" />
            )}
          </div>

          <div className="space-y-1.5">
            <h3 className="text-xl font-semibold text-white tracking-tight">
              {isUploading ? 'Uploading Security Scan Target...' : 'Drag and drop your project archive here'}
            </h3>
            <p className="text-xs sm:text-sm text-[#9aa0a6]">
              Supports <span className="font-mono text-[#8ab4f8] font-semibold bg-[#4285f4]/10 px-1.5 py-0.5 rounded border border-[#4285f4]/20">.zip</span> archives up to 600 MB
            </p>
          </div>

          {!isUploading && (
            <button
              type="button"
              className="px-6 py-2.5 rounded-full bg-gradient-to-r from-[#1a73e8] to-[#4285f4] hover:shadow-[0_0_20px_rgba(66,133,244,0.4)] text-white text-xs font-semibold transition-all shadow-md active:scale-95"
            >
              Browse Zip Archive
            </button>
          )}

          {isUploading && (
            <div className="w-full max-w-md mt-4 space-y-2">
              <div className="h-2 w-full bg-white/[0.06] rounded-full overflow-hidden border border-white/[0.08]">
                <div
                  className="h-full bg-gradient-to-r from-[#4285f4] via-[#a142f4] to-[#24c1e0] transition-all duration-300 rounded-full"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
              <p className="text-xs text-[#9aa0a6] font-mono">Uploading: {uploadProgress}%</p>
            </div>
          )}
        </div>
      </div>

      {errorMessage && (
        <div className="p-4 rounded-xl bg-[#ea4335]/10 border border-[#ea4335]/30 text-[#fad2cf] text-sm flex items-start gap-3 shadow-md">
          <AlertCircle className="w-5 h-5 text-[#ea4335] flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold text-white">Archive Upload Rejected</div>
            <div className="mt-0.5 text-xs text-[#fad2cf]">{errorMessage}</div>
          </div>
        </div>
      )}

      {/* Safety & Hardening Features Highlights with Antigravity Card Styling */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5 pt-2">
        <div className="agy-glass-card rounded-xl p-4 text-left flex items-start gap-3 border border-white/[0.08]">
          <div className="w-7 h-7 rounded-lg bg-[#34a853]/10 border border-[#34a853]/20 flex items-center justify-center flex-shrink-0 mt-0.5">
            <ShieldAlert className="w-3.5 h-3.5 text-[#34a853]" />
          </div>
          <div className="text-xs">
            <span className="font-semibold text-[#e8eaed] block tracking-tight">Zip-Slip Traversal Guard</span>
            <span className="text-[#9aa0a6] text-[11px] leading-relaxed">Rejects traversal sequences & canonical path escapes</span>
          </div>
        </div>
        <div className="agy-glass-card rounded-xl p-4 text-left flex items-start gap-3 border border-white/[0.08]">
          <div className="w-7 h-7 rounded-lg bg-[#34a853]/10 border border-[#34a853]/20 flex items-center justify-center flex-shrink-0 mt-0.5">
            <ShieldAlert className="w-3.5 h-3.5 text-[#34a853]" />
          </div>
          <div className="text-xs">
            <span className="font-semibold text-[#e8eaed] block tracking-tight">Zip-Bomb Ratio Shield</span>
            <span className="text-[#9aa0a6] text-[11px] leading-relaxed">Enforces &le; 100x uncompressed-to-compressed limit</span>
          </div>
        </div>
        <div className="agy-glass-card rounded-xl p-4 text-left flex items-start gap-3 border border-white/[0.08]">
          <div className="w-7 h-7 rounded-lg bg-[#34a853]/10 border border-[#34a853]/20 flex items-center justify-center flex-shrink-0 mt-0.5">
            <ShieldAlert className="w-3.5 h-3.5 text-[#34a853]" />
          </div>
          <div className="text-xs">
            <span className="font-semibold text-[#e8eaed] block tracking-tight">Symlink 0xA1ED Defense</span>
            <span className="text-[#9aa0a6] text-[11px] leading-relaxed">Rejects POSIX links targeting sensitive system files</span>
          </div>
        </div>
      </div>
    </div>
  );
};
