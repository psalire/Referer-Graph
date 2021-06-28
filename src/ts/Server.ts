
import express from 'express';
import * as path from 'path';

export default class Server {
    readonly app: express.Application = express();
    port: number;

    constructor(port=8888) {
        this.port = port;
        this.app.set('view engine', 'pug');
        this.app.set('views', path.resolve(__dirname, '../src/pug'));
    }

    start(): void {
        this.app.get('/', (_, res) => {
            res.render('index', {
                title: 'Home',
                header: 'Home',
                body: 'Welcome home!'
            });
        });

        this.app.listen(this.port, () => {
            console.log(`Listening at http://localhost:${this.port}`);
        });
    }
}
