module.exports = {
  mode: 'development',
  target: 'node',
  module: {
    rules: [{
      test: /\.js$/,
      exclude: /node_modules/,
      use: [{
        loader: 'babel-loader',
      }],
    }],
  },
  resolve: {
    alias: {
      'pg-native': 'noop2',
      tedious: 'noop2',
      sqlite3: 'noop2',
      mysql2: 'noop2',
    },
  },
};
