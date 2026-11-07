import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'An Error Occurred',
  message,
  onRetry
}) => {
  return (
    <div className="rounded-xl border border-rose-900/50 bg-rose-950/20 p-6 text-center space-y-4">
      <div className="inline-flex rounded-full bg-rose-900/40 p-3 text-rose-400 border border-rose-800/40">
        <AlertTriangle className="w-6 h-6" />
      </div>
      <div>
        <h3 className="text-base font-semibold text-rose-200">{title}</h3>
        <p className="text-xs text-rose-300/80 mt-1 max-w-md mx-auto">{message}</p>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-rose-900/60 hover:bg-rose-900 text-rose-100 border border-rose-700/60 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Retry Request</span>
        </button>
      )}
    </div>
  );
};
