var pkg = require('./package.json');
var webpack = require('webpack');

module.exports = {
  devtool: 'source-map',
  entry: {
    filename: './dist/commonjs/proteus.window.js',
  },
  output: {
    filename: 'proteus.js',
    libraryTarget: 'var',
    path: './dist/window',
  },
  node: {
    fs: 'empty',
    crypto: 'empty',
  },
  externals: {
    'libsodium-wrappers-sumo': 'sodium',
  },
  plugins: [
    new webpack.BannerPlugin(`${pkg.name} v${pkg.version}`)
  ],
  performance: {
    maxAssetSize: 100,
    maxEntrypointSize: 300,
    hints: 'warning',
  },
};
