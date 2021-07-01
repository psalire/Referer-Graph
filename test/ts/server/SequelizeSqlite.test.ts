
import SqliteDatabase from "../../../src/ts/server/SqliteDatabase";
import * as fs from "fs";

var db: SqliteDatabase|null = null;

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
    await db.close();
    // rmDefaultTestSqliteFile();
});

test('Create default-test.sqlite', (done) => {
    db = new SqliteDatabase('./sqlite-dbs','default-test.sqlite');
    expect(db).not.toBeNull();
    db.authenticate().then(() => {
        done();
    });
});

test('Open test-existing.sqlite', () => {
    new SqliteDatabase('./sqlite-dbs','test-existing.sqlite');
});

test('Sync hosts table', (done) => {
    db.hosts.sync().then(() => {
        done();
    })
});

test('Insert one into hosts table', async () => {
    await db.hosts.insert(['example.com'], '/');
    let models = await db.hosts.selectAll();
    expect(models.length).toBe(1);
    console.log(models[0]);
    expect(models[0].host).toBe('example.com');
});

test('Insert multiple into hosts table', async () => {
    let testVals = [
        'example1.com',
        'example2.com',
        'example3.com'
    ]
    for (let testVal of testVals) {
        await db.hosts.insert([testVal], '/');
    }

    let models = await db.hosts.selectAll();
    expect(models.length).toBe(4);

    expect(models[0].host).toBe('example.com');
    for (let i=1; i<4; i++) {
        expect(models[i].host).toBe(testVals[i-1]);
    }

    let testVals2 = [
        'test.com',
        'test1.com',
        'test2.com',
        'test3.com',
        'test4.com',
        'test5.com',
    ];
    await db.hosts.bulkInsert(testVals2.map((val)=>{
        return [val];
    }));

    models = await db.hosts.selectAll();
    expect(models.length).toBe(10);

    expect(models[0].host).toBe('example.com');
    for (let i=1; i<4; i++) {
        expect(models[i].host).toBe(testVals[i-1]);
    }
    expect(models[4].host).toBe('test.com');
    for (let i=5; i<10; i++) {
        expect(models[i].host).toBe(testVals2[i-4]);
    }
})
