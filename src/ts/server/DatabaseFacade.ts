
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
        return this.sqliteDb.hosts.bulkInsert(protocols.map(val=>[val]));
    }

    public addHost(host: string, protocol: string): Promise<any> {
        return this.sqliteDb.hosts.insert([host, protocol]);
    }
    public addHosts(hosts: string[], protocol: string): Promise<any> {
        return this.sqliteDb.hosts.bulkInsert(hosts.map(val=>[val]), protocol);
    }

    public addPath(path: string, host: string): Promise<any> {
        return this.sqliteDb.paths.insert([path, host]);
    }
    public addPaths(paths: string[], host: string): Promise<any> {
        return this.sqliteDb.paths.bulkInsert(paths.map(val=>[val]), host);
    }

    public addPathQuery(query: string, path: string): Promise<any> {
        return this.sqliteDb.queries.insert([query, path]);
    }
    public addPathQueries(queries: string[], path: string): Promise<any> {
        return this.sqliteDb.queries.bulkInsert(queries.map(val=>[val]), path);
    }

    public addSrcDstMapping(
        srcDst: string[], srcHost: string, dstHost?: string
    ): Promise<any> {
        return this.sqliteDb.srcDsts.insert(srcDst, srcHost, dstHost);
    }
    public addSrcDstMappings(
        srcDsts: string[][], srcHost: string, dstHost?: string
    ): Promise<any> {
        return this.sqliteDb.srcDsts.bulkInsert(srcDsts, srcHost, dstHost);
    }

    public updateDBPath(dbPath: string, dbName: string) {
        this.sqliteDb.setDB(dbPath, dbName);
    }
}
