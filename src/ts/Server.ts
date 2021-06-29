
import express from 'express';
import * as path from 'path';

export default class Server {
    readonly app: express.Application = express();
    port: number;

    constructor(port=8000) {
        this.port = port;
        this.app.use(express.json());
        this.app.set('view engine', 'pug');
        this.app.set('views', path.resolve(__dirname, '../src/pug'));
    }

    start(): void {
        this.app.all('*', (req, _, next) => {
            console.log(`${req.method} ${req.originalUrl}`);
            next();
        });

        this.app.get('/', (_, res) => {
            res.render('index', {
                title: 'Home',
                header: 'Home',
                content: 'Welcome home!'
            });
        });

        this.app.post('/request', (req, res) => {
            console.log(req.body);
            res.status(200).end();
        });

        this.app.listen(this.port, () => {
            console.log(`Listening at http://localhost:${this.port}`);
        });
    }
}
