/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Theme-aware semantic colors (powered by CSS custom properties)
        background: {
          DEFAULT: 'rgb(var(--bg) / <alpha-value>)',
          elevated: 'rgb(var(--bg-elevated) / <alpha-value>)',
          card: 'rgb(var(--bg-card) / <alpha-value>)',
        },
        surface: {
          DEFAULT: 'rgb(var(--surface) / <alpha-value>)',
          hover: 'rgb(var(--surface-hover) / <alpha-value>)',
        },
        foreground: {
          DEFAULT: 'rgb(var(--fg) / <alpha-value>)',
          secondary: 'rgb(var(--fg-secondary) / <alpha-value>)',
          muted: 'rgb(var(--fg-muted) / <alpha-value>)',
        },
        border: {
          DEFAULT: 'rgb(var(--border-color) / <alpha-value>)',
          strong: 'rgb(var(--border-strong) / <alpha-value>)',
        },
        accent: {
          cyan: 'rgb(var(--accent) / <alpha-value>)',
          glow: 'rgb(var(--accent-glow) / <alpha-value>)',
        },

        // Severity colors (same in both themes — high contrast)
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#6b7280',
          clean: '#22c55e',
        },

        // Node accent colors (same in both themes)
        node: {
          plugin: '#64748b',
          skill: '#6366f1',
          command: '#8b5cf6',
          hook: '#f59e0b',
          mcp: '#06b6d4',
          lsp: '#14b8a6',
          agent: '#10b981',
          script: '#f43f5e',
          resource: '#6b7280',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 20px rgba(34, 211, 238, 0.3)',
        'glow-critical': '0 0 20px rgba(239, 68, 68, 0.4)',
        'glow-high': '0 0 15px rgba(249, 115, 22, 0.3)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px currentColor' },
          '100%': { boxShadow: '0 0 20px currentColor, 0 0 30px currentColor' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
}
