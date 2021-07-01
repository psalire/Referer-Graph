
import Database from 'better-sqlite3';
import * as path from 'path';

export default class SqliteDatabase {

    private db: Database.Database|null;
    private dbPath: string;
    // private dbName: string|null;

    // public constructor(dbPath="./sqlite-dbs", dbName=null) {
    public constructor(dbPath="./sqlite-dbs") {
        this.dbPath = dbPath;
        // this.dbName = dbName;
        this.db = null;
    }

    private initializeDb(dbName: string, fileMustExist=false): Database.Database {
        return new Database(
            path.join(this.dbPath, dbName),
            { fileMustExist: fileMustExist }
        );
    }

    private createTable(tableName: string, columns: string): SqliteDatabase {
        if (!this.db) {
            throw new SqliteDatabaseError(
                'Database hasn\'t been initialized. Call createAndOpenDb() or openDb().'
            );
        }
        this.db.prepare(`CREATE TABLE ?(${columns})`).run(tableName);
        return this;
    }

    public createAndOpenDb(dbName: string): SqliteDatabase {
        if (this.openDb(dbName, true)) {
            throw new SqliteDatabaseError(`Database "${dbName}" already exists`);
        }
        this.db = this.initializeDb(dbName);
        return this;
    }

    public openDb(dbName: string, checkOnly=false): SqliteDatabase {
        let dbObj = this.initializeDb(dbName, true);
        if (!checkOnly) {
            // this.dbName = dbName;
            this.db = dbObj;
        }
        return this;
    }

    public createHostTable(host: string): SqliteDatabase {
        return this.createTable(host, 'path VARCHAR(512)');
    }

    public createSourcePathTable(path: string): SqliteDatabase {
        return this.createTable(path, 'destPath VARCHAR(1024)');
    }
}
