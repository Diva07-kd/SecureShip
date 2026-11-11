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
        sans: ['"Google Sans Flex"', '"Google Sans"', 'Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"Google Sans Code"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      colors: {
        agy: {
          bg: '#0d0e12',
          card: '#131419',
          surface: '#18191f',
          elevated: '#21232b',
          blue: '#4285f4',
          'blue-dark': '#1a73e8',
          cyan: '#24c1e0',
          purple: '#a142f4',
          emerald: '#34a853',
          amber: '#fbbc04',
          coral: '#ea4335',
          text: '#e8eaed',
          muted: '#9aa0a6',
          dim: '#5f6368',
        },
        severity: {
          critical: '#ea4335',
          high: '#fa7b17',
          medium: '#fbbc04',
          low: '#4285f4',
          info: '#9aa0a6',
        }
      },
      backgroundImage: {
        'agy-gradient': 'linear-gradient(135deg, #4285f4 0%, #a142f4 50%, #24c1e0 100%)',
        'agy-glow': 'radial-gradient(ellipse at 50% -20%, rgba(66, 133, 244, 0.15) 0%, rgba(161, 66, 244, 0.08) 40%, transparent 70%)',
      },
      boxShadow: {
        'agy-card': '0 14px 36px -4px rgba(0, 0, 0, 0.5), 0 4px 12px -2px rgba(0, 0, 0, 0.3)',
        'agy-glow': '0 0 25px rgba(66, 133, 244, 0.35)',
        'agy-pill': '0 2px 8px rgba(0, 0, 0, 0.25)',
      }
    },
  },
  plugins: [],
}
