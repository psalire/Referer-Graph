
import SqliteDatabase from "../../../src/ts/server/SqliteDatabase";
import SqliteDatabaseError from "../../../src/ts/server/SqliteDatabaseError";
import * as fs from "fs";
import * as path from "path";
import { ValidationError, SequelizeUniqueConstraintError } from 'sequelize';

var db: SqliteDatabase|null = null;
const dbsPath = './test/sqlite-dbs';
const PROTOCOL = 'https';

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
    await db.protocols.insert([PROTOCOL]);
    await db.hosts.insert([testVal, PROTOCOL]);
    let models = await db.hosts.selectAll();
    expect(models.length).toBe(1);
    expect(models[0].host).toBe(testVal);
});

test('Insert bulk into hosts table', async () => {
    let testVals = [
        'example1.com',
        'example2.com',
        'example3.com'
    ]
    for (let testVal of testVals) {
        await db.hosts.insert([testVal, PROTOCOL]);
    }

    let models = await db.hosts.selectAll();
    expect(models.length).toBe(4);

    expect(models[0].host).toBe('example.com');
    for (let i=0; i<testVals.length; i++) {
        expect(models[i+1].host).toBe(testVals[i]);
    }

    let testVals2 = [
        'test.com',
        'test1.com',
        'test2.com',
        'www.test3.com',
        'www.test4.com',
        'test.test5.com',
    ];
    await db.hosts.bulkInsert(testVals2.map(val=>[val]), PROTOCOL);

    models = await db.hosts.selectAll();
    expect(models.length).toBe(10);
    let hosts = models.map(val=>val.host);
    for (let host of hosts) {
        expect(testVals.concat(testVals2).concat("example.com")).toContain(host);
    }
});

test('Insert duplicate hosts', async () => {
    expect(await db.hosts.insert(['apple.com', PROTOCOL])).not.toBeNull();
    for (let i=0; i<5; i++) {
        expect(await db.hosts.insert(['apple.com', PROTOCOL])).toBeNull();
    }
});

test('Insert into paths table', async () => {
    await db.paths.insert(['/', 'example.com'], PROTOCOL);
    let models = await db.paths.selectAll();
    expect(models.length).toBe(1);
    expect(models[0].path).toBe('/');

    let vals = [
        [['/index.html', 'example.com']],
        [['/word.exe', 'example.com']],
        [['/a/path/file', 'test.test5.com']],
        [['/home', 'www.test3.com']],
    ];
    for (let val of vals) {
        await db.paths.insert(val[0], PROTOCOL);
    }
    models = await db.paths.selectAll();
    expect(models.length).toBe(5);
    let paths = models.map(val=>val.path);
    let hosts = models.map(async (val)=>{
        return (await val.getHost()).host
    });
    hosts = await Promise.all(hosts);
    let testPaths = (vals.map(val=>val[0][0])).concat("/");
    let testHosts = vals.map(val=>val[0][1]);
    for (let path of paths) {
        expect(testPaths).toContain(path);
    }
    for (let host of hosts) {
        expect(testHosts).toContain(host);
    }
});

test('Insert bulk into paths table', async () => {
    await db.hosts.insert(['yahoo.com', PROTOCOL]);
    let vals = [
        '/', '/page/1', '/page/2',
        '/page/3', '/page/4', '/page/5',
        '/page/6', '/page/7', '/page/8',
    ];
    await db.paths.bulkInsert(vals.map(v=>[v]), 'yahoo.com', PROTOCOL);
    let hostObj = await db.hosts.selectOne({
        host: 'yahoo.com'
    });
    let models = await db.paths.selectAll({
        HostId: hostObj.id
    });
    expect(models.length).toBe(9);
    for (let i=0; i<models.length; i++) {
        expect(models[i].path).toBe(vals[i]);
    }
});

test('Insert duplicate paths', async () => {
    for (let i=0; i<5; i++) {
        expect(await db.paths.insert(['/index.html', 'example.com'], PROTOCOL)).toBeNull();
    }
});

test('Insert path with non-existing host', async () => {
    await expect(db.paths.insert(['/abcd'], 'google.com')).rejects.toThrow(SqliteDatabaseError);
});

test('Insert into srcDst table', async () => {
    let vals = [
        [['/', '/index.html'], 'example.com'],
        [['/index.html', '/word.exe'], 'example.com'],
        [['/word.exe', '/index.html'], 'example.com', 'example.com']
    ]
    for (let val of vals) {
        await db.srcDsts.insert(val[0], PROTOCOL, PROTOCOL, val[1]);
    }
    let models = await db.srcDsts.selectAll();
    expect(models.length).toBe(vals.length);
    for (let i=0; i<models.length; i++) {
        let srcObj = await db.paths.selectByPk(models[i].srcPathId);
        let dstObj = await db.paths.selectByPk(models[i].dstPathId);
        let val = vals[i];
        expect(srcObj.path).toBe(val[0][0]);
        expect(dstObj.path).toBe(val[0][1]);
        expect((await srcObj.getHost()).host).toBe(val[1]);
        expect((await dstObj.getHost()).host).toBe(val.length==3 ? val[2] : val[1]);
    }
});

test('Insert cross host into srcDst table', async () => {
    let vals = [
        [['/index.html', '/home'], 'example.com', 'www.test3.com'],
        [['/word.exe', '/home'], 'example.com', 'www.test3.com'],
        [['/home', '/a/path/file'], 'www.test3.com', 'test.test5.com']
    ]
    for (let val of vals) {
        await db.srcDsts.insert(val[0], PROTOCOL, PROTOCOL, val[1], val[2]);
    }
    // let models = await db.srcDsts.selectAll(undefined, [['updatedAt', 'ASC']]);
    // expect(models.length).toBe(6);
    // for (let i=models.length-vals.length; i<models.length; i++) {
    //     let srcObj = await db.paths.selectByPk(models[i].srcPathId);
    //     let dstObj = await db.paths.selectByPk(models[i].dstPathId);
    //     let val = vals[i-(models.length-vals.length)];
    //     expect(srcObj.path).toBe(val[0][0]);
    //     expect(dstObj.path).toBe(val[0][1]);
    //     expect((await srcObj.getHost()).host).toBe(val[1]);
    //     expect((await dstObj.getHost()).host).toBe(val[2]);
    // }
});

test('Insert bulk into srcDst table', async () => {
    let vals = [
        ['/abcd', '/efgh'],
        ['/ijkl', '/mnop'],
        ['/qrst', '/uvwx'],
        ['/yz', '/abcd'],
    ];
    expect(await db.paths.bulkInsert(vals.flat().map(v=>[v]), 'yahoo.com', PROTOCOL)).toBeNull();
    for (let val of vals.flat()) {
        await db.paths.insert([val, 'yahoo.com'], PROTOCOL);
    }
    await db.srcDsts.bulkInsert(vals, PROTOCOL, PROTOCOL, 'yahoo.com');
});

test('Insert duplicate into srcDst table', async () => {
    for (let i=0; i<5; i++) {
        expect(await db.srcDsts.insert(['/abcd', '/efgh'], PROTOCOL, PROTOCOL, 'yahoo.com')).toBeNull();
    }
});

test('Insert non-existing paths & hosts into srcDst table', async () => {
    expect(async ()=>{await db.srcDsts.insert(['/non', '/exist'], PROTOCOL, PROTOCOL, 'nonexist.com')}).rejects.toThrow();
    expect(async ()=>{await db.srcDsts.insert(['/nonx', '/existx'], PROTOCOL, PROTOCOL, 'yahoo.com')}).rejects.toThrow();
    expect(async ()=>{await db.srcDsts.insert(['/non', '/exist'], PROTOCOL, PROTOCOL, 'yahoo.com')}).rejects.toThrow();

    // let hostObj = await db.hosts.selectOne({
    //     host: 'nonexist.com'
    // });
    // let srcPathObj = await db.paths.selectOne({
    //     path: '/non',
    //     HostId: hostObj.id
    // });
    // let dstPathObj = await db.paths.selectOne({
    //     path: '/exist',
    //     HostId: hostObj.id
    // });
    // let srcModels = await db.srcDsts.selectAll({
    //     srcPathId: srcPathObj.id
    // });
    // let dstModels = await db.srcDsts.selectAll({
    //     dstPathId: dstPathObj.id
    // });
    // expect(srcModels.length).toBe(1);
    // expect(dstModels.length).toBe(1);
})
