
import SqliteDatabase from "../../../src/ts/server/SqliteDatabase";
import * as fs from "fs";
import * as path from "path";

var db: SqliteDatabase|null = null;

const dbsPath = './test/sqlite-dbs'

function rmDefaultTestSqliteFile() {
    try {
        fs.rmSync(path.join(dbsPath, 'default-test.sqlite'));
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
    await db.close();
    // rmDefaultTestSqliteFile();
});

test('Create default-test.sqlite', (done) => {
    db = new SqliteDatabase(dbsPath, 'default-test.sqlite');
    expect(db).not.toBeNull();
    db.authenticate().then(() => {
        done();
    });
});

test('Open test-existing.sqlite', () => {
    new SqliteDatabase(dbsPath, 'test-existing.sqlite');
});

test('Sync hosts table', (done) => {
    db.hosts.sync().then(() => {
        done();
    })
});

test('Insert one into hosts table', async () => {
    const testVal = 'https://example.com/'
    await db.hosts.insert([testVal]);
    let models = await db.hosts.selectAll();
    expect(models.length).toBe(1);
    console.log(models[0]);
    expect(models[0].host).toBe(testVal);
});

test('Insert bulk into hosts table', async () => {
    let testVals = [
        'http://www.example1.com/',
        'https://www.example2.com/',
        'https://example3.com/'
    ]
    for (let testVal of testVals) {
        await db.hosts.insert([testVal]);
    }

    let models = await db.hosts.selectAll();
    expect(models.length).toBe(4);

    expect(models[0].host).toBe('https://example.com/');
    for (let i=1; i<4; i++) {
        expect(models[i].host).toBe(testVals[i-1]);
    }

    let testVals2 = [
        'http://test.com',
        'https://test1.com',
        'https://www.test2.com',
        'https://www.test3.com',
        'http://www.test4.com',
        'https://test.test5.com',
    ];
    await db.hosts.bulkInsert(testVals2.map((val)=>{
        return [val];
    }));

    models = await db.hosts.selectAll();
    expect(models.length).toBe(10);

    expect(models[0].host).toBe('https://example.com/');
    for (let i=1; i<4; i++) {
        expect(models[i].host).toBe(testVals[i-1]);
    }
    expect(models[4].host).toBe(testVals2[0]);
    for (let i=5; i<10; i++) {
        expect(models[i].host).toBe(testVals2[i-4]);
    }
})
