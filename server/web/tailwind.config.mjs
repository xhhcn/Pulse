/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{astro,html,js,ts,jsx,tsx}'],
	darkMode: 'class', // Enable class-based dark mode
	theme: {
		extend: {
			// Beszel's radius (0.8rem): its md (10.8 px) for controls and rows,
			// which Pulse writes rounded-lg, and its lg (12.8 px) for cards and
			// dialogs, which Pulse writes rounded-xl.
			borderRadius: {
				lg: '0.675rem',
				xl: '0.8rem',
			},
			colors: {
				surface: '#151515',
				panel: '#1c1c1c',
				accent: '#10b981',
				warn: '#f59e0b',
				// 纯中性灰色
				'neutral-50': '#fafafa',
				'neutral-100': '#f5f5f5',
				'neutral-200': '#e5e5e5',
				'neutral-300': '#d4d4d4',
				'neutral-400': '#a3a3a3',
				'neutral-500': '#737373',
				'neutral-600': '#525252',
				'neutral-700': '#404040',
				'neutral-800': '#262626',
				'neutral-900': '#181818',
			},
		},
	},
	plugins: [],
};

