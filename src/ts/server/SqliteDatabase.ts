
import { Sequelize, DataTypes, Model, ModelCtor } from 'sequelize';
import * as path from 'path';
import HostsTable from './HostsTable';
import PathsTable from './PathsTable';
import SrcDstTable from './SrcDstTable';

export default class SqliteDatabase {
    private sequelize: Sequelize;
    public hosts: HostsTable;
    public paths: PathsTable;
    public srcDst: SrcDstTable;
    // private hostPathTables: Map<string,ModelCtor<Model>>;
    // private srcDstTables: Map<string,ModelCtor<Model>>;

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
        var pathsModel = this.sequelize.define(
            'Path',
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
        var srcDstModel = this.sequelize.define(
            'SrcDst',
            {
                src: {
                    type: DataTypes.INTEGER,
                    allowNull: false
                },
                dst: {
                    type: DataTypes.INTEGER,
                    allowNull: false
                }
            },
            {
                timestamps: false
            }
        );

        pathsModel.hasMany(hostsModel);
        hostsModel.belongsTo(pathsModel);
        srcDstModel.hasMany(pathsModel);
        pathsModel.belongsTo(srcDstModel);

        this.hosts = new HostsTable(hostsModel);
        this.paths = new PathsTable(pathsModel);
        this.srcDst = new SrcDstTable(srcDstModel);

        this.sync();

        // this.hostPathTables = new Map();
        // this.srcDstTables = new Map();
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
