
import SequelizeSqlite from "../../../src/ts/server/SequelizeSqlite";
import * as fs from "fs";

var db: SequelizeSqlite|null = null;

function rmDefaultTestSqliteFile() {
    try {
        fs.rmSync('./sqlite-dbs/default-test.sqlite');
    }
    catch(e) {
        if (e.code!=='ENOENT') {
            throw e;
        }
    }
}

beforeAll(() => {
    rmDefaultTestSqliteFile();
});
afterAll(async () => {
    await db.closeDb();
    rmDefaultTestSqliteFile();
});

test('Create default-test.sqlite', (done) => {
    db = new SequelizeSqlite('./sqlite-dbs','default-test.sqlite');
    expect(db).not.toBeNull();
    db.authenticate().then(() => {
        done();
    });
});

test('Open test-existing.sqlite', () => {
    new SequelizeSqlite('./sqlite-dbs','test-existing.sqlite');
});

test('Sync hosts table', (done) => {
    db.syncHosts().then(() => {
        done();
    })
});

test('Insert one into hosts table', async () => {
    await db.insertHost('example.com');
    let models = await db.selectAllHosts();
    expect(models.length).toBe(1);
    console.log(models[0]);
    expect(models[0].host).toBe('example.com');
});

test('Insert multiple into hosts table', async () => {
    await db.insertHost('example1.com');
    await db.insertHost('example2.com');
    await db.insertHost('example3.com');

    let models = await db.selectAllHosts();
    expect(models.length).toBe(4);

    expect(models[0].host).toBe('example.com');
    for (let i=1; i<4; i++) {
        expect(models[i].host).toBe(`example${i}.com`);
    }

    await db.bulkInsertHosts([
        'test.com',
        'test1.com',
        'test2.com',
        'test3.com',
        'test4.com',
        'test5.com',
    ]);

    models = await db.selectAllHosts();
    expect(models.length).toBe(10);

    expect(models[0].host).toBe('example.com');
    for (let i=1; i<4; i++) {
        expect(models[i].host).toBe(`example${i}.com`);
    }
    expect(models[4].host).toBe('test.com');
    for (let i=5; i<10; i++) {
        expect(models[i].host).toBe(`test${i-4}.com`);
    }
})
