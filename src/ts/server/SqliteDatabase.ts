
import Database from 'better-sqlite3';
import * as path from 'path';

export default class SqliteDatabase {

    db: Database.Database|null;
    dbPath: string;
    dbName: string|null;

    constructor(dbPath="./sqlite-dbs", dbName=null) {
        this.dbPath = dbPath;
        this.dbName = dbName;
        this.db = null;
    }

    openDb(dbName: string): boolean {
        try {
            this.db = new Database(
                path.join(this.dbPath, dbName),
                {fileMustExist: true}
            );
            this.dbName = dbName;
            return true;
        }
        catch (e) {
            console.error(e);
            return false;
        }
    }

    createHost(): boolean {
        if (this.db==null) {
            return false;
        }
        try {
            this.db.prepare(
                'CREATE TABLE test(col1 VARCHAR(10), col2 VARCHAR(20))'
            ).run();
            return true;
        }
        catch(e) {
            console.error(e);
            return false;
        }
    }
}
