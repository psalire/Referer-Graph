
import SqliteDatabase from "../../../src/ts/server/SqliteDatabase";
import * as fs from "fs";

var db: SqliteDatabase|null = null;
const dbFilename = './sqlite-dbs/test.db';

function cleanup() {
    try {
        fs.rmSync(dbFilename);
    }
    catch(e) {
        if (e.code!=='ENOENT') {
            throw e;
        }
    }
}

beforeAll(() => {
    cleanup();
});
afterAll(() => {
    db && db.closeDb();
    cleanup();
});

test('Initialize SqliteDatabase', () => {
    db = new SqliteDatabase();
    // db = new SqliteDatabase(String.raw`C:\Users\PhilipSalire\Documents\app-flow-visualizer`);
    expect(db).not.toBeNull();
});

test('Create database', () => {
    db.createAndOpenDb('test.db');
    expect(fs.openSync('./sqlite-dbs/test.db', 'r')).not.toBe(-1);
});

test('Create hosts table', () => {
    db.createHostsTable('example.com');
    expect(db.selectAllHosts().length).toBe(0);
});

test('Insert into hosts table', () => {
    db.insertHost('example.com');
    expect(db.selectAllHosts().length).toBe(1);
    expect(db.selectAllHosts()).toEqual([
        {'host':'example.com'}
    ]);

    db.insertHost('example1.com');
    db.insertHost('example2.com');
    expect(db.selectAllHosts().length).toBe(3);
    expect(db.selectAllHosts()).toEqual([
        {'host':'example.com'},
        {'host':'example1.com'},
        {'host':'example2.com'}
    ]);
});
