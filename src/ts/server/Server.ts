
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
    private isSaveToSqliteOn: boolean = false;

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

    private async insertURLToDB(requestData: {[key: string]: any}, headers?: string): Promise<any> {
        await this.db.addProtocol(requestData.protocol);
        await this.db.addHost(requestData.host, requestData.protocol);
        await this.db.addPath(requestData.path, requestData.host, requestData.protocol);
        await this.db.addPathQuery(requestData.query, requestData.path, requestData.host, requestData.protocol);
    }

    public start(): void {
        this.app.all('*', (req, _, next) => {
            console.log(`[${req.ip}]: ${req.method} ${req.originalUrl}`);
            next();
        });

        this.app.get('/', (_, res) => {
            res.render('index', {title: 'Referer Graph'});
        });

        this.app.post('/request', async (req, res) => {
            console.log(req.body);
            var statusCode = 204;
            var requestData = req.body.requestData;
            var responseData = req.body.responseData;
            if (this.isSaveToSqliteOn==true && req.body.save==true) {
                try {
                    await this.insertURLToDB(requestData);
                    await this.db.addHeader(
                        requestData.headers, responseData.headers, requestData.path, requestData.host, requestData.protocol
                    );
                    if (requestData.referer) {
                        await this.insertURLToDB(requestData.referer, responseData.headers);
                        await this.db.addMethod(requestData.method);
                        await this.db.addSrcDstMapping(
                            [
                                requestData.referer.path,
                                requestData.path,
                                requestData.method
                            ],
                            requestData.referer.protocol,
                            requestData.protocol,
                            requestData.referer.host,
                            requestData.host
                        );
                    }
                }
                catch(e) {
                    console.error(e);
                    statusCode = 500;
                }
            }
            this.io.emit('data', req.body);

            res.status(statusCode).end();
        });

        this.app.post('/sqlite/:isSqliteOn', (req, res) => {
            var statusCode = 204;
            var isSqliteOnStr = req.params.isSqliteOn.toUpperCase();
            if (isSqliteOnStr=='ON') {
                this.isSaveToSqliteOn = true;
            }
            else if (isSqliteOnStr=='OFF') {
                this.isSaveToSqliteOn = false;
            }
            else {
                statusCode = 400;
                console.log(`Invalid argument`);
            }

            res.status(statusCode).end();
        });

        this.app.post('/filepath', (req, res) => {
            console.log(req.body);
            var statusCode = 204;
            try {
                this.db.updateDBPath(req.body.path, req.body.filename);
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
