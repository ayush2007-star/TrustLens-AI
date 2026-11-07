/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0B0F19",
          card: "#111827",
          cardHover: "#162032",
          border: "#1F2937",
          borderSubtle: "#374151",
          primary: "#3B82F6",
          accent: "#06B6D4",
          purple: "#8B5CF6",
          textMain: "#F9FAFB",
          textMuted: "#9CA3AF"
        },
        risk: {
          low: "#10B981",
          suspicious: "#F59E0B",
          high: "#EF4444",
          malicious: "#DC2626",
          inconclusive: "#64748B"
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif']
      }
    },
  },
  plugins: [],
}
