import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { LandingPage } from './pages/LandingPage';
import { DashboardPage } from './pages/DashboardPage';
import { InvestigateUrlPage } from './pages/InvestigateUrlPage';
import { InvestigationDetailPage } from './pages/InvestigationDetailPage';
import { MessageAnalyzerPage } from './pages/MessageAnalyzerPage';
import { TlsAnalysisPage } from './pages/TlsAnalysisPage';
import { SecurityAssessmentPage } from './pages/SecurityAssessmentPage';
import { ThreatIntelCenterPage } from './pages/ThreatIntelCenterPage';
import { ThreatCorrelationPage } from './pages/ThreatCorrelationPage';
import { DigitalTrustRegistryPage } from './pages/DigitalTrustRegistryPage';
import { HistoryPage } from './pages/HistoryPage';
import { MethodologyPage } from './pages/MethodologyPage';

export function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-[#0B0F19] text-[#F9FAFB]">
        {/* Persistent Cyber Sidebar */}
        <Sidebar />

        {/* Main Content Area */}
        <div className="flex flex-col flex-1 min-w-0">
          <Navbar />
          <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">
            <Routes>
              <Route path="/" element={<LandingPage />} />
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/investigate" element={<InvestigateUrlPage />} />
              <Route path="/investigations/:id" element={<InvestigationDetailPage />} />
              <Route path="/message-analyzer" element={<MessageAnalyzerPage />} />
              <Route path="/tls-trust" element={<TlsAnalysisPage />} />
              <Route path="/security-assessment" element={<SecurityAssessmentPage />} />
              <Route path="/threat-intel" element={<ThreatIntelCenterPage />} />
              <Route path="/threat-correlation" element={<ThreatCorrelationPage />} />
              <Route path="/trust-registry" element={<DigitalTrustRegistryPage />} />
              <Route path="/history" element={<HistoryPage />} />
              <Route path="/methodology" element={<MethodologyPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}

export default App;
