module.exports = {
  plugins: [
    require('tailwindcss'),
    // Beszel's tinted greys: warm in the light theme, cool in the dark one.
    require('./postcss-tint-neutrals.cjs')(),
    require('autoprefixer'),
  ]
};
