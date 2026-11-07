import React from 'react';

interface BrandLogoProps {
  size?: 'sm' | 'md' | 'lg';
  showTagline?: boolean;
}

export const BrandLogo: React.FC<BrandLogoProps> = ({ size = 'md', showTagline = false }) => {
  const iconSizes = {
    sm: 'w-7 h-7',
    md: 'w-9 h-9',
    lg: 'w-12 h-12'
  };

  const textSizes = {
    sm: 'text-lg',
    md: 'text-xl',
    lg: 'text-2xl'
  };

  return (
    <div className="flex items-center gap-3 select-none">
      {/* Custom SVG Brand Mark: Hexagonal Shield + Digital Eye + Trust Core */}
      <div className={`relative flex items-center justify-center ${iconSizes[size]} rounded-lg bg-gradient-to-br from-blue-900/60 to-cyan-950/80 border border-cyan-500/30 p-1.5 shadow-lg shadow-cyan-950/40`}>
        <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
          {/* Outer Protective Shield Geometry */}
          <path
            d="M24 4L40 10V22C40 33.2 33.2 41.5 24 44C14.8 41.5 8 33.2 8 22V10L24 4Z"
            stroke="#06B6D4"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="opacity-90"
          />
          {/* Inner Optical Lens / Cyber Eye Arc */}
          <path
            d="M14 24C17 18 31 18 34 24C31 30 17 30 14 24Z"
            stroke="#3B82F6"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          {/* Core Trust Pulse Point */}
          <circle cx="24" cy="24" r="3.5" fill="#38BDF8" className="animate-pulse" />
        </svg>
      </div>

      <div className="flex flex-col">
        <div className="flex items-center gap-1.5">
          <span className={`font-black tracking-wider text-white ${textSizes[size]}`}>
            TRUST<span className="text-cyan-400">LENS</span>
          </span>
          <span className="px-1.5 py-0.5 text-[10px] font-bold tracking-widest text-blue-400 bg-blue-950/70 border border-blue-500/30 rounded">
            AI
          </span>
        </div>
        {showTagline && (
          <span className="text-[11px] font-medium tracking-wide text-gray-400 uppercase">
            Investigate. Understand. Verify. Protect.
          </span>
        )}
      </div>
    </div>
  );
};
