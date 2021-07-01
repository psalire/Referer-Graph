
import SqliteDatabase from "../../../src/ts/server/SqliteDatabase";

var db=null;

test('Initialize SqliteDatabase', () => {
    db = new SqliteDatabase();
    expect(db).not.toBeNull();
});
