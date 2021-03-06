
const path = require('path');
const scriptsPath = './src/ts/scripts/';

module.exports = {
    mode: 'development',
    entry: {
        'sidebar': path.resolve(scriptsPath, 'sidebar.ts'),
        'settings': path.resolve(scriptsPath, 'settings.ts'),
        'graph': path.resolve(scriptsPath, 'graph.ts'),
        'bootstrap-collapse': './node_modules/bootstrap/js/dist/collapse.js'
    },
    devtool: 'eval-source-map',
    output: {
        filename: '[name].js',
        path: path.resolve('./public/static/js/')
    },
    module: {
        rules: [
            {
                test: /\.(t|j)s$/,
                exclude: /node_modules/,
                loader: 'babel-loader'
            }
        ],
    },
    resolve: {
        extensions: ['.ts', '.js']
    }
};
