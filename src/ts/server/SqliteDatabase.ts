
import { Sequelize, DataTypes } from 'sequelize';
import * as path from 'path';
import HostsTable from './HostsTable';
import PathsTable from './PathsTable';
import SrcDstTable from './SrcDstTable';

export default class SqliteDatabase {
    private sequelize: Sequelize;
    public hosts: HostsTable;
    public paths: PathsTable;
    public srcDst: SrcDstTable;

    public constructor(dbPath='./sqlite-dbs', dbName='default.sqlite') {
        this.sequelize = new Sequelize({
            dialect: 'sqlite',
            storage: path.join(dbPath, dbName),
            logging: false
        });

        var hostsModel = this.sequelize.define(
            'Host',
            {
                host: {
                    type: DataTypes.TEXT,
                    allowNull: false,
                    unique: true
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
            {},
            {
                timestamps: false
            }
        );

        hostsModel.hasMany(pathsModel);
        pathsModel.belongsTo(hostsModel);
        pathsModel.hasMany(srcDstModel, {
            as: 'src',
            foreignKey: {
                name: 'srcPathId',
                allowNull: false
            }
        });
        pathsModel.hasMany(srcDstModel, {
            as: 'dst',
            foreignKey: {
                name: 'dstPathId',
                allowNull: false
            }
        });
        // srcDstModel.belongsTo(pathsModel);

        this.hosts = new HostsTable(hostsModel);
        this.paths = new PathsTable(pathsModel, hostsModel);
        this.srcDst = new SrcDstTable(srcDstModel, pathsModel, hostsModel);

        this.sync();
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
