
import Database from 'better-sqlite3';
import SqliteDatabaseError from './SqliteDatabaseError';
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
    private prepareQuery(query: string): Database.Statement {
        if (!this.db) {
            throw new SqliteDatabaseError(
                'Database hasn\'t been initialized. Call createAndOpenDb() or openDb().'
            );
        }
        return this.db.prepare(query);
    }

    private createTable(tableName: string, columns: string): SqliteDatabase {
        this.prepareQuery(`CREATE TABLE ${tableName}(${columns});`).run();
        return this;
    }
    private insertInto(tableName: string, values: string[]) {
        this.prepareQuery(
            `INSERT INTO ${tableName} VALUES(${Array(values.length).fill('?')})`
        ).run(...values);
        return this;
    }
    public createHostsTable(): SqliteDatabase {
        return this.createTable('hosts', 'host TEXT NOT NULL UNIQUE');
    }
    public createHostPathsTable(host: string): SqliteDatabase {
        return this.createTable(host, 'path TEXT NOT NULL UNIQUE');
    }
    public createSrcDstPathTable(path: string): SqliteDatabase {
        return this.createTable(path, 'dest TEXT NOT NULL UNIQUE');
    }
    public insertHost(host: string): SqliteDatabase {
        return this.insertInto('hosts', [host]);
    }
    public selectAllHosts(): object[] {
        return this.prepareQuery(`SELECT * FROM hosts;`).all();
    }

    public openDb(dbName: string, checkOnly=false): SqliteDatabase {
        let dbObj = this.initializeDb(dbName, true);
        if (!checkOnly) {
            // this.dbName = dbName;
            this.db = dbObj;
        }
        else {
            dbObj.close();
        }
        return this;
    }
    public createAndOpenDb(dbName: string): SqliteDatabase {
        try {
            this.openDb(dbName, true);
            throw new SqliteDatabaseError(`Database "${dbName}" already exists`);
        }
        catch(e) {
            // Not error due to non-existent db file
            if (!((e instanceof Database.SqliteError) && e.message=='unable to open database file')) {
                throw e;
            }
        }
        this.db = this.initializeDb(dbName);
        return this;
    }
    public closeDb(): void {
        this.db && this.db.close();
    }
}
