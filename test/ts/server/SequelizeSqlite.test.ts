
import SqliteDatabase from "../../../src/ts/server/SqliteDatabase";
import SqliteDatabaseError from "../../../src/ts/server/SqliteDatabaseError";
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

test('Sync hosts table', async () => {
    await db.hosts.sync();
});

test('Insert one into hosts table', async () => {
    const testVal = 'example.com'
    await db.hosts.insert([testVal]);
    let models = await db.hosts.selectAll();
    expect(models.length).toBe(1);
    console.log(models[0]);
    expect(models[0].host).toBe(testVal);
});

test('Insert bulk into hosts table', async () => {
    let testVals = [
        'example1.com',
        'example2.com',
        'example3.com'
    ]
    for (let testVal of testVals) {
        await db.hosts.insert([testVal]);
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
        'www.test3.com',
        'www.test4.com',
        'test.test5.com',
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
    expect(models[4].host).toBe(testVals2[0]);
    for (let i=5; i<10; i++) {
        expect(models[i].host).toBe(testVals2[i-4]);
    }
});

test('Insert into paths table', async () => {
    await db.paths.insert(['/'], 'example.com');
    let models = await db.paths.selectAll();
    expect(models.length).toBe(1);
    expect(models[0].path).toBe('/');

    await db.paths.insert(['/index.html'], 'example.com');
    await db.paths.insert(['/word.exe'], 'example.com');
    await db.paths.insert(['/a/path/file'], 'test.test5.com');
    await db.paths.insert(['/home'], 'www.test3.com');
    models = await db.paths.selectAll();
    expect(models.length).toBe(5);
    expect(models[0].path).toBe('/');
    expect(models[1].path).toBe('/index.html');
    expect(models[2].path).toBe('/word.exe');
    expect(models[3].path).toBe('/a/path/file');
    expect(models[4].path).toBe('/home');
    expect((await models[0].getHost()).host).toBe('example.com');
    expect((await models[1].getHost()).host).toBe('example.com');
    expect((await models[2].getHost()).host).toBe('example.com');
    expect((await models[3].getHost()).host).toBe('test.test5.com');
    expect((await models[4].getHost()).host).toBe('www.test3.com');

});

test('Insert path with non-existing host', async () => {
    await expect(db.paths.insert(['/abcd'], 'google.com')).rejects.toThrow(SqliteDatabaseError);
});

test('Insert into srcDst table', async () => {
    await db.srcDsts.insert(['/', '/index.html'], 'example.com');
});
