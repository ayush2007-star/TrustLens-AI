import React, { useState } from 'react';
import {
  MessageSquareWarning,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Cpu,
  ArrowRight,
  Send,
  Sparkles,
  Lock
} from 'lucide-react';
import { apiClient } from '../api/client';
import { MessageAnalysisResponse } from '../types';
import { RiskBadge } from '../components/RiskBadge';
import { ErrorState } from '../components/ErrorState';

const SAMPLE_MESSAGES = [
  {
    label: 'Banking OTP Smishing',
    category: 'High Risk',
    text: 'URGENT: Your Chase banking account has been temporarily suspended due to unusual activity. Reply with your 6-digit one-time password OTP immediately to prevent permanent account lock.'
  },
  {
    label: 'Fake Delivery Fee',
    category: 'High Risk',
    text: 'USPS Notice: Your package #US9405 cannot be delivered due to an incorrect street address. Pay $1.99 customs release fee at http://tinyurl.com/usps-resched within 24 hours to claim.'
  },
  {
    label: 'Tech Support Remote Access',
    category: 'Critical',
    text: 'Microsoft Security Alert: Critical Trojan detected on your computer! Your banking credentials may be compromised. Call +1-800-555-0199 immediately and install AnyDesk for remote tech assistance.'
  },
  {
    label: 'Benign Appointment Reminder',
    category: 'Low Risk',
    text: 'Hi Sarah, this is a reminder for your dental checkup tomorrow at 2:00 PM with Dr. Miller. Please reply C to confirm or call 555-0123 to reschedule.'
  }
];

export const MessageAnalyzerPage: React.FC = () => {
  const [messageText, setMessageText] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<MessageAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (textToScan: string) => {
    if (!textToScan.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await apiClient.analyzeMessage(textToScan.trim());
      setResult(data);
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.response?.data?.message || err.message || 'Analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleAnalyze(messageText);
  };

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="border-b border-slate-800/80 pb-4">
        <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
          <MessageSquareWarning className="w-6 h-6 text-purple-400" />
          Scam & Social Engineering Analyzer
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Apply local deterministic rules to identify pressure tactics, credential harvesting, advance-fee demands, and remote access lures.
        </p>
      </div>

      {/* Safety Notice */}
      <div className="flex items-center gap-2.5 p-3 rounded-lg border border-blue-500/30 bg-blue-950/20 text-xs text-blue-300">
        <Lock className="w-4 h-4 text-cyan-400 shrink-0" />
        <span>
          <strong>Data Privacy:</strong> Analysis uses local deterministic rules. Submitted text is not stored; only redacted indicators and analysis metadata are retained. Avoid entering real credentials or account numbers.
        </span>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-xl space-y-4">
        <div className="space-y-2">
          <label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center justify-between">
            <span>Paste Suspicious Message (SMS, WhatsApp, Email, or Job Offer)</span>
            <span className="text-[11px] text-slate-500 font-normal">{messageText.length} characters</span>
          </label>
          <textarea
            rows={5}
            value={messageText}
            onChange={(e) => setMessageText(e.target.value)}
            placeholder="Paste message contents here (e.g., 'URGENT: Your account has been suspended. Reply with your OTP...')..."
            className="w-full rounded-lg bg-slate-950 border border-slate-800 p-3 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono transition"
            disabled={loading}
          />
        </div>

        {/* Quick Sample Lures */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
          <span className="text-[11px] font-bold text-slate-500 uppercase">Sample Lures:</span>
          {SAMPLE_MESSAGES.map((sample, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setMessageText(sample.text);
                handleAnalyze(sample.text);
              }}
              className="px-2.5 py-1 rounded-md bg-slate-800/80 hover:bg-slate-800 text-slate-300 border border-slate-700/60 text-[11px] transition"
            >
              {sample.label}
            </button>
          ))}
        </div>

        <div className="flex justify-end pt-2">
          <button
            type="submit"
            disabled={loading || messageText.trim().length < 5}
            className="flex items-center gap-2 px-6 py-2.5 rounded-lg text-xs font-bold uppercase tracking-wider bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white transition shadow-lg shadow-purple-950/40"
          >
            {loading ? (
              <>
                <span className="w-3.5 h-3.5 rounded-full border-2 border-white border-t-transparent animate-spin" />
                <span>Analyzing Patterns...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5" />
                <span>Analyze Message</span>
              </>
            )}
          </button>
        </div>
      </form>

      {error && <ErrorState message={error} />}

      {/* Analysis Result Display */}
      {result && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-2xl space-y-6 animate-fadeIn">
          {/* Header Verdict */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
            <div className="space-y-1">
              <div className="flex items-center gap-3">
                <RiskBadge level={result.risk_level} size="lg" />
                <span className="text-xs font-mono text-slate-400">
                  Confidence: <strong className="text-slate-200">{result.confidence}</strong>
                </span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-purple-400 flex items-center gap-1">
                  <Cpu className="w-3 h-3" />
                  Engine: {result.analyzed_via}
                </span>
              </div>
              <h3 className="text-base font-bold text-white pt-2">{result.summary}</h3>
            </div>

            <div className="text-center px-4 py-2 rounded-xl bg-slate-950 border border-slate-800 shrink-0">
              <span className="text-2xl font-black font-mono text-white">
                {result.risk_score}
                <span className="text-xs text-slate-500 font-sans">/100</span>
              </span>
              <p className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold">
                Threat Score
              </p>
            </div>
          </div>

          {/* Simple Language Explanation */}
          <div className="space-y-1.5">
            <h4 className="text-xs font-bold uppercase tracking-wider text-purple-400">
              Psychological & Behavioral Evaluation
            </h4>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed bg-slate-950/60 p-4 rounded-lg border border-slate-800">
              {result.explanation}
            </p>
          </div>

          {/* Identified Threat Indicators */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-white">
              Detected Manipulation Indicators ({result.indicators.length})
            </h4>

            {result.indicators.length === 0 ? (
              <p className="text-xs text-slate-500 p-3 rounded-lg bg-slate-950 border border-slate-800">
                No acute social engineering or credential harvesting patterns identified.
              </p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {result.indicators.map((ind, i) => (
                  <div key={i} className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-white">{ind.title}</span>
                      <RiskBadge level={ind.severity} size="sm" />
                    </div>
                    <div className="rounded bg-slate-900 p-2 font-mono text-xs text-rose-300 border border-slate-800/80">
                      <span className="text-slate-500 text-[10px] uppercase font-bold block">Quoted Text:</span>
                      "{ind.evidence_snippet}"
                    </div>
                    <p className="text-xs text-slate-400 leading-normal">{ind.reasoning}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Recommended Precautions */}
          <div className="rounded-lg bg-purple-950/20 border border-purple-500/30 p-4 space-y-2">
            <h4 className="text-xs font-bold text-purple-300 uppercase tracking-wider">
              Recommended Protective Precautions
            </h4>
            <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
              {result.recommended_precautions.map((rec, i) => (
                <li key={i}>{rec}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
};
