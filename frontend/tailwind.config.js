/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      colors: {
        agy: {
          bg: '#f6f6f1',
          card: '#ffffff',
          surface: '#ffffff',
          elevated: '#edf0e9',
          blue: '#557b37',
          'blue-dark': '#405f2b',
          cyan: '#b4c2a6',
          purple: '#82956f',
          emerald: '#718c4f',
          amber: '#d29b2e',
          coral: '#ea4335',
          text: '#252d27',
          muted: '#69746b',
          dim: '#7c877e',
        },
        severity: {
          critical: '#ea4335',
          high: '#fa7b17',
        medium: '#d29b2e',
        low: '#557b37',
        info: '#69746b',
        }
      },
      backgroundImage: {
        'agy-gradient': 'linear-gradient(135deg, #405f2b 0%, #557b37 55%, #82956f 100%)',
      },
      boxShadow: {
        'agy-card': '0 4px 14px -4px rgba(31, 43, 35, 0.08), 0 1px 4px rgba(31, 43, 35, 0.04)',
        'agy-glow': '0 0 20px rgba(85, 123, 55, 0.18)',
        'agy-pill': '0 2px 8px rgba(31, 43, 35, 0.06)',
      }
    },
  },
  plugins: [],
}
