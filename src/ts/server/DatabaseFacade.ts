
import SqliteDatabase from './SqliteDatabase';

export default class DatabaseFacade {
    private sqliteDb : SqliteDatabase;

    public constructor(dbPath='./sqlite-dbs', dbName='default.sqlite') {
        this.sqliteDb = new SqliteDatabase(dbPath, dbName);
    }

    public addProtocol(protocol: string): Promise<any> {
        return this.sqliteDb.protocols.insert([protocol]);
    }
    public addProtocols(protocols: string[]): Promise<any> {
        return this.sqliteDb.protocols.bulkInsert(protocols.map(val=>[val]));
    }

    public addHost(host: string, protocol: string): Promise<any> {
        return this.sqliteDb.hosts.insert([host, protocol]);
    }
    public addHosts(hosts: string[], protocol: string): Promise<any> {
        return this.sqliteDb.hosts.bulkInsert(hosts.map(val=>[val]), protocol);
    }

    public addPath(path: string, host: string, protocol: string): Promise<any> {
        return this.sqliteDb.paths.insert([path, host], protocol);
    }
    public addPaths(paths: string[], host: string, protocol: string): Promise<any> {
        return this.sqliteDb.paths.bulkInsert(paths.map(val=>[val]), host, protocol);
    }

    public addPathQuery(query: string, path: string, host: string, protocol: string): Promise<any> {
        return this.sqliteDb.queries.insert([query, path], protocol, host);
    }
    public addPathQueries(queries: string[], path: string, host: string, protocol: string): Promise<any> {
        return this.sqliteDb.queries.bulkInsert(queries.map(val=>[val]), path, protocol, host);
    }

    public addMethod(method: string): Promise<any> {
        return this.sqliteDb.methods.insert([method]);
    }
    public addMethods(methods: string[]): Promise<any> {
        return this.sqliteDb.methods.bulkInsert(methods.map(val=>[val]));
    }

    public addHeader(reqHeaders: string, resHeaders: string, path: string, host: string, protocol: string): Promise<any> {
        return this.sqliteDb.headers.insert([reqHeaders, resHeaders, path], protocol, host);
    }
    public addHeaders(headers: string[][], path: string, host: string, protocol: string): Promise<any> {
        return this.sqliteDb.headers.bulkInsert(headers, path, protocol, host);
    }

    public addSrcDstMapping(
        srcDst: string[], srcProtocol: string, dstProtocol: string,
        srcHost: string, dstHost?: string
    ): Promise<any> {
        return this.sqliteDb.srcDsts.insert(srcDst, srcProtocol, dstProtocol, srcHost, dstHost);
    }
    public addSrcDstMappings(
        srcDsts: string[][], srcProtocol: string, dstProtocol: string,
        srcHost: string, dstHost?: string
    ): Promise<any> {
        return this.sqliteDb.srcDsts.bulkInsert(srcDsts, srcProtocol, dstProtocol, srcHost, dstHost);
    }

    public updateDBPath(dbPath: string, dbName: string) {
        this.sqliteDb.setDB(dbPath, dbName);
    }
}
