/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        obsidian: {
          950: '#030509',
          900: '#060911',
          850: '#0B101D',
          800: '#0F172A',
          700: '#1E293B',
        },
        cyber: {
          cyan: '#00F2FE',
          cyanDim: 'rgba(0, 242, 254, 0.15)',
          violet: '#8B5CF6',
          violetDim: 'rgba(139, 92, 246, 0.15)',
          blue: '#38BDF8',
          crimson: '#EF4444',
          amber: '#F59E0B',
          emerald: '#10B981',
        }
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      animation: {
        'radar-sweep': 'sweep 4s linear infinite',
        'pulse-glow': 'pulseGlow 2.5s ease-in-out infinite',
        'marquee': 'marquee 28s linear infinite',
        'marquee-reverse': 'marqueeRev 32s linear infinite',
        'float-slow': 'float 6s ease-in-out infinite',
        'float-delayed': 'float 7s ease-in-out 2s infinite',
        'scanline': 'scanline 8s linear infinite',
      },
      keyframes: {
        sweep: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        pulseGlow: {
          '0%, 100%': { opacity: '0.4', transform: 'scale(0.98)' },
          '50%': { opacity: '1', transform: 'scale(1.02)' },
        },
        marquee: {
          '0%': { transform: 'translateX(0%)' },
          '100%': { transform: 'translateX(-50%)' },
        },
        marqueeRev: {
          '0%': { transform: 'translateX(-50%)' },
          '100%': { transform: 'translateX(0%)' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-8px)' },
        },
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        }
      }
    },
  },
  plugins: [],
}
