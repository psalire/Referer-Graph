
import { Sequelize, DataTypes, Model, ModelCtor } from 'sequelize';
import * as path from 'path';

export default class SequlizeSqlite {
    private sequelize: Sequelize;
    private hostTable: ModelCtor<Model>;
    private hostPathTables: Map<string,ModelCtor<Model>>;
    private srcDstTables: Map<string,ModelCtor<Model>>;

    public constructor(dbPath='./sqlite-dbs', dbName='default.sqlite') {
        this.sequelize = new Sequelize({
            dialect: 'sqlite',
            storage: path.join(dbPath, dbName)
        });
        this.hostTable = this.sequelize.define(
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
        );
        this.hostPathTables = new Map();
        this.srcDstTables = new Map();
    }

    public syncHosts(): Promise<any> {
        return this.hostTable.sync();
    }
    public insertHost(host: string): Promise<any> {
        return this.hostTable.create({
            host: host
        });
    }
    public bulkInsertHosts(hosts: string[]) {
        return this.hostTable.bulkCreate(hosts.map(host => {
            return {host: host}
        }));
    }
    public selectAllHosts(): Promise<Model[]> {
        return this.hostTable.findAll({
            attributes: ['host']
        });
    }

    public authenticate(): Promise<any> {
        return this.sequelize.authenticate();
    }
    public closeDb(): Promise<any> {
        return this.sequelize.close();
    }
}
