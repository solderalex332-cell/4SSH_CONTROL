/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js,ts}'],
  theme: {
    extend: {
      colors: {
        bastion: {
          900: '#070b14',
          800: '#0c1322',
          700: '#111b30',
          600: '#1a2744',
          500: '#243558',
          400: '#3a506e',
        },
        neon: {
          cyan: '#00e5ff',
          green: '#39ff14',
          red: '#ff1744',
          yellow: '#ffd600',
          purple: '#d500f9',
          blue: '#2979ff',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ["'JetBrains Mono'", 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
}
