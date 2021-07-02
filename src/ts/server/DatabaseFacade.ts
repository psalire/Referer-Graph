
import SqliteDatabase from './SqliteDatabase';

export default class DatabaseFacade {
    private sqliteDb : SqliteDatabase;

    public constructor(dbPath='./sqlite-dbs', dbName='default.sqlite') {
        this.sqliteDb = new SqliteDatabase(dbPath, dbName);
    }

    public addHost(host: string): Promise<any> {
        return this.sqliteDb.hosts.insert([host]);
    }
    public addHosts(hosts: string[]): Promise<any> {
        return this.sqliteDb.hosts.bulkInsert(hosts.map(val=>[val]));
    }

    public addPath(path: string, host: string): Promise<any> {
        return this.sqliteDb.paths.insert([path], host);
    }
    public addPaths(paths: string[], host: string): Promise<any> {
        return this.sqliteDb.paths.bulkInsert(paths.map(val=>[val]), host);
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
}
