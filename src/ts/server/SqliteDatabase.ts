
import { Sequelize, DataTypes } from 'sequelize';
import * as path from 'path';
import HostsTable from './HostsTable';
import PathsTable from './PathsTable';
import SrcDstTable from './SrcDstTable';

export default class SqliteDatabase {
    private sequelize: Sequelize;
    private filepath: string;
    public hosts: HostsTable;
    public paths: PathsTable;
    public srcDsts: SrcDstTable;

    public constructor(dbPath='./sqlite-dbs', dbName='default.sqlite') {
        this.setDB(dbPath, dbName);
    }

    public setDB(dbPath: string, dbName: string) {
        console.log(dbPath);
        console.log(dbName);
        var resolvedPath = path.resolve(path.join(dbPath, dbName));
        if (resolvedPath==this.filepath) {
            console.log(`[SqliteDatabase] ${resolvedPath} is already active`);
            return;
        }
        this.filepath = resolvedPath;
        console.log(`[SqliteDatabase] Set new db ${resolvedPath}`);

        this.sequelize = new Sequelize({
            dialect: 'sqlite',
            storage: this.filepath,
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
                timestamps: true,
                createdAt: false
            }
        );
        var pathsModel = this.sequelize.define(
            'Path',
            {
                path: {
                    type: DataTypes.TEXT,
                    allowNull: false,
                    unique: 'pathsComposite'
                },
                HostId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    unique: 'pathsComposite',
                    references: {
                        model: hostsModel,
                        key: 'id'
                    }
                }
            },
            {
                timestamps: true,
                createdAt: false
            }
        );
        var srcDstModel = this.sequelize.define(
            'SrcDst',
            {
                srcPathId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    unique: 'srcDstComposite',
                    references: {
                        model: pathsModel,
                        key: 'id'
                    }
                },
                dstPathId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    unique: 'srcDstComposite',
                    references: {
                        model: pathsModel,
                        key: 'id'
                    }
                }
            },
            {
                timestamps: true,
                createdAt: false
            }
        );

        hostsModel.hasMany(pathsModel, {
            foreignKey: {
                allowNull: false
            }
        });
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

        this.hosts = new HostsTable(hostsModel);
        this.paths = new PathsTable(pathsModel, hostsModel);
        this.srcDsts = new SrcDstTable(srcDstModel, pathsModel, hostsModel);

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
