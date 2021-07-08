
import DatabaseFacade from './DatabaseFacade';
import express from 'express';
import { createServer, Server as HttpServer} from 'http';
import { Server as IOServer , Socket as IOSocket } from 'socket.io';
import * as path from 'path';

export default class Server {
    private readonly app: express.Application = express();
    private httpServer: HttpServer;
    private io: IOServer;
    private db: DatabaseFacade;
    private port: number;

    public constructor(port=8000) {
        this.port = port;
        this.app.use(express.json());
        this.app.use(express.static('./public/'));
        this.app.set('view engine', 'pug');
        this.app.set('views', path.resolve(__dirname, '../../src/pug'));
        this.db = new DatabaseFacade();
        this.httpServer = createServer(this.app);
        this.io = new IOServer(this.httpServer, {
            serveClient: false
        });
    }

    public start(): void {
        this.app.all('*', (req, _, next) => {
            console.log(`[${req.ip}]: ${req.method} ${req.originalUrl}`);
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
            var statusCode = 204;
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
                this.io.emit('data', requestData);
            }
            catch(e) {
                console.error(e);
                statusCode = 500;
            }

            res.status(statusCode).end();
        });

        this.io.on("connection", (socket: IOSocket) => {
            console.log(`socket ${socket.id} connected!`);
        });

        this.httpServer.listen(this.port, () => {
            console.log(`Listening at http://localhost:${this.port}`);
        });
    }
}
