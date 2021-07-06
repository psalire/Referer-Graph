
const path = require('path');

module.exports = {
    mode: 'development',
    entry: './src/ts/scripts/graph.ts',
    devtool: 'eval-source-map',
    output: {
        filename: 'graph.js',
        path: path.resolve('./public/static/js/')
    },
    module: {
        rules: [
            {
                test: /\.(t|j)s$/,
                exclude: /node_modules/,
                loader: 'babel-loader'
            }
        ]
    },
    resolve: {
        extensions: ['.ts', '.js']
    }
};
