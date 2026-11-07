import React, { useState } from 'react';
import { Copy, Check, ChevronDown, ChevronUp, Code } from 'lucide-react';

interface EvidencePanelProps {
  title: string;
  data: any;
  defaultExpanded?: boolean;
}

export const EvidencePanel: React.FC<EvidencePanelProps> = ({
  title,
  data,
  defaultExpanded = false
}) => {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const [copied, setCopied] = useState(false);

  const jsonString = typeof data === 'string' ? data : JSON.stringify(data, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 bg-slate-900/90 border-b border-slate-800/80">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-2 text-xs font-semibold text-slate-300 hover:text-white transition"
        >
          <Code className="w-4 h-4 text-cyan-400" />
          <span>{title}</span>
          {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>

        <button
          onClick={handleCopy}
          className="flex items-center gap-1 text-[11px] font-mono text-slate-400 hover:text-cyan-300 transition px-2 py-1 rounded bg-slate-800/60 hover:bg-slate-800 border border-slate-700/50"
          title="Copy raw JSON evidence"
        >
          {copied ? (
            <>
              <Check className="w-3 h-3 text-emerald-400" />
              <span className="text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3" />
              <span>Copy Evidence</span>
            </>
          )}
        </button>
      </div>

      {expanded && (
        <pre className="p-4 bg-slate-950 font-mono text-xs text-cyan-300/90 overflow-x-auto max-h-80 border-t border-slate-900 leading-relaxed">
          {jsonString}
        </pre>
      )}
    </div>
  );
};
