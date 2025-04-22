const path = require('path');

module.exports = {
  mode: 'development',
  entry: './browser-entry.js',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'),
    libraryTarget: 'window',
  },
  experiments: {
    topLevelAwait: true,
  },
};
