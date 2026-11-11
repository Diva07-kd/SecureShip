import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { ScanPage } from './pages/ScanPage';
import { ReportPage } from './pages/ReportPage';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-[#0d0e12] text-[#e8eaed] flex flex-col font-sans relative overflow-x-hidden">
        {/* Subtle Ambient Antigravity Glow Orbs */}
        <div className="pointer-events-none fixed -top-40 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-gradient-to-b from-[#4285f4]/15 via-[#a142f4]/10 to-transparent blur-3xl rounded-full -z-10" />
        <div className="pointer-events-none fixed top-1/3 -right-40 w-[450px] h-[450px] bg-[#24c1e0]/5 blur-[120px] rounded-full -z-10" />

        <Navbar />
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 relative z-10">
          <Routes>
            <Route path="/" element={<Navigate to="/scan" replace />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/report/:job_id" element={<ReportPage />} />
            <Route path="/report/:id" element={<ReportPage />} />
            <Route path="*" element={<Navigate to="/scan" replace />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </BrowserRouter>
  );
};
