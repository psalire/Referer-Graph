
import Database from 'better-sqlite3';
import * as path from 'path';

export default class SqliteDatabase {

    private db: Database.Database|null;
    private dbPath: string;
    private dbName: string|null;

    public constructor(dbPath="./sqlite-dbs", dbName=null) {
        this.dbPath = dbPath;
        this.dbName = dbName;
        this.db = null;
    }

    public openDb(dbName: string): boolean {
        try {
            this.db = new Database(
                path.join(this.dbPath, dbName),
                {
                    fileMustExist: true
                }
            );
            this.dbName = dbName;
            return true;
        }
        catch (e) {
            console.error(e);
            return false;
        }
    }

    public createHostTable(host: string): boolean {
        try {
            if (this.db) {
                this.db.prepare(
                    'CREATE TABLE ?(path VARCHAR(1024))'
                ).run(host);
                return true;
            }
            return false;
        }
        catch(e) {
            console.error(e);
            return false;
        }
    }

    public createPath(path: string): boolean {
        try {
            if (this.db) {
                this.db.prepare(
                    'CREATE TABLE ?(path VARCHAR(1024))'
                ).run(path);
                return true;
            }
            return false;
        }
        catch(e) {
            console.error(e);
            return false;
        }
    }
}
