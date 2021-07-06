
import DatabaseFacade from './DatabaseFacade';
import express from 'express';
import http from 'http';
import * as path from 'path';

export default class Server {
    private readonly app: express.Application = express();
    private server: http.Server;
    private db: DatabaseFacade;
    private port: number;

    public constructor(port=8000) {
        this.port = port;
        this.app.use(express.json());
        this.app.use(express.static('./public/'));
        this.app.set('view engine', 'pug');
        this.app.set('views', path.resolve(__dirname, '../../src/pug'));
        this.db = new DatabaseFacade();
    }

    public start(): void {
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

        this.app.post('/request', async (req, res) => {
            console.log(req.body);
            var statusCode = 200;
            try {
                var requestData = req.body.requestData;
                // var responseData = req.body.respsonseData;

                await this.db.addHost(requestData.host);
                await this.db.addPath(requestData.path, requestData.host);
                if (requestData.referer) {
                    await this.db.addSrcDstMapping(
                        [requestData.referer.path, requestData.path],
                        requestData.referer.host,
                        requestData.host
                    );
                }
            }
            catch(e) {
                console.error(e);
                statusCode = 500;
            }

            res.status(statusCode).end();
        });

        this.server = http.createServer(this.app);
        this.server.listen(this.port, () => {
            console.log(`Listening at http://localhost:${this.port}`);
        });
    }
}
