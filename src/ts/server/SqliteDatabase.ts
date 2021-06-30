
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

    private createTable(tableName: string, columns: string): boolean {
        try {
            if (this.db) {
                this.db.prepare(
                    `CREATE TABLE ?(${columns})`
                ).run(tableName);
                return true;
            }
            return false;
        }
        catch(e) {
            console.error(e);
            return false;
        }
    }

    public createHostTable(host: string): boolean {
        return this.createTable(host, 'path VARCHAR(512)');
    }

    public createSourcePathTable(path: string): boolean {
        return this.createTable(path, 'destPath VARCHAR(1024)');
    }
}
