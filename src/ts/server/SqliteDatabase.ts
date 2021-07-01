
import { Sequelize, DataTypes, Model, ModelCtor } from 'sequelize';
import * as path from 'path';
import HostsTable from './HostsTable';

export default class SqliteDatabase {
    private sequelize: Sequelize;
    public hosts: HostsTable;
    private hostPathTables: Map<string,ModelCtor<Model>>;
    private srcDstTables: Map<string,ModelCtor<Model>>;

    public constructor(dbPath='./sqlite-dbs', dbName='default.sqlite') {
        this.sequelize = new Sequelize({
            dialect: 'sqlite',
            storage: path.join(dbPath, dbName)
        });
        this.hosts = new HostsTable(this.sequelize.define(
            'Host',
            {
                host: {
                    type: DataTypes.TEXT,
                    allowNull: false
                }
            },
            {
                timestamps: false
            }
        ));
        this.hostPathTables = new Map();
        this.srcDstTables = new Map();
    }

    public authenticate(): Promise<any> {
        return this.sequelize.authenticate();
    }
    public closeDb(): Promise<any> {
        return this.sequelize.close();
    }
}
