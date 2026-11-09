import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { apiClient } from './api/client';

const LandingPage = React.lazy(() => import('./pages/LandingPage').then((module) => ({ default: module.LandingPage })));
const DashboardPage = React.lazy(() => import('./pages/DashboardPage').then((module) => ({ default: module.DashboardPage })));
const InvestigateUrlPage = React.lazy(() => import('./pages/InvestigateUrlPage').then((module) => ({ default: module.InvestigateUrlPage })));
const InvestigationDetailPage = React.lazy(() => import('./pages/InvestigationDetailPage').then((module) => ({ default: module.InvestigationDetailPage })));
const MessageAnalyzerPage = React.lazy(() => import('./pages/MessageAnalyzerPage').then((module) => ({ default: module.MessageAnalyzerPage })));
const TlsAnalysisPage = React.lazy(() => import('./pages/TlsAnalysisPage').then((module) => ({ default: module.TlsAnalysisPage })));
const SecurityAssessmentPage = React.lazy(() => import('./pages/SecurityAssessmentPage').then((module) => ({ default: module.SecurityAssessmentPage })));
const ThreatIntelCenterPage = React.lazy(() => import('./pages/ThreatIntelCenterPage').then((module) => ({ default: module.ThreatIntelCenterPage })));
const ThreatCorrelationPage = React.lazy(() => import('./pages/ThreatCorrelationPage').then((module) => ({ default: module.ThreatCorrelationPage })));
const DigitalTrustRegistryPage = React.lazy(() => import('./pages/DigitalTrustRegistryPage').then((module) => ({ default: module.DigitalTrustRegistryPage })));
const HistoryPage = React.lazy(() => import('./pages/HistoryPage').then((module) => ({ default: module.HistoryPage })));
const MethodologyPage = React.lazy(() => import('./pages/MethodologyPage').then((module) => ({ default: module.MethodologyPage })));

export function App() {
  return (
    <AccessGate>
      <ApplicationRoutes />
    </AccessGate>
  );
}

function AccessGate({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<'checking' | 'unlocked' | 'locked' | 'unavailable'>('checking');
  const [token, setToken] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    const initialize = async () => {
      try {
        const queryParams = new URLSearchParams(window.location.search);
        const urlToken = queryParams.get('token');
        if (urlToken) {
          apiClient.setAccessToken(urlToken.trim());
        }

        const health = await apiClient.getHealth();
        if (!health.access_control_required) {
          if (active) setStatus('unlocked');
          return;
        }

        if (!apiClient.getAccessToken()) {
          if (active) setStatus('locked');
          return;
        }

        await apiClient.checkAccess();
        if (active) setStatus('unlocked');
      } catch {
        apiClient.clearAccessToken();
        if (active) {
          setError('The access token is invalid or the API is unavailable.');
          setStatus('locked');
        }
      }
    };
    void initialize();
    return () => {
      active = false;
    };
  }, []);

  const unlock = async (event: React.FormEvent) => {
    event.preventDefault();
    apiClient.setAccessToken(token.trim());
    setError('');
    try {
      await apiClient.checkAccess();
      setStatus('unlocked');
    } catch {
      apiClient.clearAccessToken();
      setError('Access was denied. Check the token and try again.');
      setStatus('locked');
    }
  };

  if (status === 'unlocked') return <>{children}</>;

  return (
    <main className="min-h-screen bg-[#0B0F19] text-[#F9FAFB] flex items-center justify-center p-4">
      {status === 'checking' ? (
        <p role="status" className="text-sm text-slate-300">Checking API access...</p>
      ) : status === 'unavailable' ? (
        <p role="alert" className="text-sm text-rose-300">{error || 'The API is unavailable.'}</p>
      ) : (
        <form onSubmit={unlock} className="w-full max-w-md space-y-4 rounded-xl border border-slate-700 bg-slate-900 p-6">
          <div>
            <h1 className="text-xl font-bold text-white">TrustLens AI access</h1>
            <p className="mt-2 text-sm text-slate-300">Enter the access token provided by the deployment owner. It is kept in this browser tab only.</p>
          </div>
          <label className="block text-sm text-slate-300" htmlFor="access-token">Access token</label>
          <input
            id="access-token"
            type="password"
            autoComplete="current-password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            required
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white"
          />
          {error && <p role="alert" className="text-sm text-rose-300">{error}</p>}
          <button type="submit" className="w-full rounded-lg bg-cyan-600 px-4 py-2 font-semibold text-white hover:bg-cyan-500">
            Continue
          </button>
        </form>
      )}
    </main>
  );
}

function ApplicationRoutes() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-[#0B0F19] text-[#F9FAFB]">
        <Sidebar />

        <div className="flex flex-col flex-1 min-w-0">
          <Navbar />
          <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">
            <React.Suspense fallback={<div className="p-8 text-slate-300">Loading security dashboard...</div>}>
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
            </React.Suspense>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}

export default App;
