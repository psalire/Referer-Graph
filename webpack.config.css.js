
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const FixStyleOnlyEntriesPlugin = require("webpack-fix-style-only-entries");
const path = require('path');
const scssDir = 'src/scss/';

module.exports = {
    mode: 'production',
    entry: {
        'main': path.resolve(scssDir, 'main.scss')
    },
    output: {
        path: path.resolve(__dirname, './public/static/css')
    },
    plugins: [
        new MiniCssExtractPlugin({
            filename: '[name].css'
        }),
        new FixStyleOnlyEntriesPlugin()
    ],
    module: {
        rules: [
            {
                test: /\.s?[ac]ss$/,
                exclude: /node_modules/,
                use: [
                    {
                        loader: MiniCssExtractPlugin.loader
                    },
                    'css-loader',
                    'sass-loader',
                    'postcss-loader'
                ]
            }
        ]
    }
};
