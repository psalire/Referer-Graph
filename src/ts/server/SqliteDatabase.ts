
import { Sequelize, DataTypes, Model, ModelCtor } from 'sequelize';
import * as path from 'path';
import HostsTable from './HostsTable';
import PathsTable from './PathsTable';

export default class SqliteDatabase {
    private sequelize: Sequelize;
    public hosts: HostsTable;
    public srcPaths: PathsTable;
    public dstPaths: PathsTable;
    private hostPathTables: Map<string,ModelCtor<Model>>;
    private srcDstTables: Map<string,ModelCtor<Model>>;

    public constructor(dbPath='./sqlite-dbs', dbName='default.sqlite') {
        this.sequelize = new Sequelize({
            dialect: 'sqlite',
            storage: path.join(dbPath, dbName)
        });

        var hostsModel = this.sequelize.define(
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
        var srcPathsModel = this.sequelize.define(
            'SrcPath',
            {
                path: {
                    type: DataTypes.TEXT,
                    allowNull: false
                }
            },
            {
                timestamps: false
            }
        );
        var dstPathsModel = this.sequelize.define(
            'DstPath',
            {
                path: {
                    type: DataTypes.TEXT,
                    allowNull: false
                }
            },
            {
                timestamps: false
            }
        );

        srcPathsModel.hasMany(hostsModel);
        hostsModel.belongsTo(srcPathsModel);
        dstPathsModel.hasMany(srcPathsModel);
        srcPathsModel.belongsTo(dstPathsModel);

        this.hosts = new HostsTable(hostsModel, srcPathsModel);
        this.srcPaths = new PathsTable(srcPathsModel);
        this.dstPaths = new PathsTable(dstPathsModel, srcPathsModel);

        this.sync();

        this.hostPathTables = new Map();
        this.srcDstTables = new Map();
    }

    public authenticate(): Promise<any> {
        return this.sequelize.authenticate();
    }
    public sync(): Promise<any> {
        return this.sequelize.sync();
    }
    public close(): Promise<any> {
        return this.sequelize.close();
    }
}
