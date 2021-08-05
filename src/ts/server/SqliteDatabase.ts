
import { Sequelize, DataTypes } from 'sequelize';
import * as path from 'path';
import ProtocolsTable from './ProtocolsTable';
import HostsTable from './HostsTable';
import PathsTable from './PathsTable';
import QueriesTable from './QueriesTable';
import SrcDstTable from './SrcDstTable';

export default class SqliteDatabase {
    private sequelize: Sequelize;
    private filepath: string;
    public protocols: ProtocolsTable;
    public hosts: HostsTable;
    public paths: PathsTable;
    public queries: QueriesTable;
    public srcDsts: SrcDstTable;

    public constructor(dbPath='./sqlite-dbs', dbName='default.sqlite') {
        this.setDB(dbPath, dbName);
    }

    public setDB(dbPath: string, dbName: string) {
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

        var protocolsModel = this.sequelize.define(
            'Protocol',
            {
                protocol: {
                    type: DataTypes.TEXT,
                    allowNull: false,
                    unique: true
                }
            },
            {
                timestamps: false,
                createdAt: false
            }
        );
        var hostsModel = this.sequelize.define(
            'Host',
            {
                host: {
                    type: DataTypes.TEXT,
                    allowNull: false,
                    unique: 'hostsComposite'
                },
                ProtocolId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    unique: 'hostsComposite',
                    references: {
                        model: protocolsModel,
                        key: 'id'
                    }
                }
            },
            {
                timestamps: false,
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
                timestamps: false,
                createdAt: false
            }
        );
        var queriesModel = this.sequelize.define(
            'Query',
            {
                query: {
                    type: DataTypes.TEXT,
                    allowNull: false,
                    unique: 'queryComposite'
                },
                PathId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    unique: 'queryComposite',
                    references: {
                        model: pathsModel,
                        key: 'id'
                    }
                }
            },
            {
                timestamps: false,
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
                timestamps: false,
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
        pathsModel.hasMany(queriesModel, {
            foreignKey: {
                allowNull: false
            }
        });

        this.protocols = new ProtocolsTable(protocolsModel);
        this.hosts = new HostsTable(hostsModel, protocolsModel);
        this.paths = new PathsTable(pathsModel, hostsModel, protocolsModel);
        this.queries = new QueriesTable(queriesModel, pathsModel);
        this.srcDsts = new SrcDstTable(srcDstModel, pathsModel, hostsModel, protocolsModel);

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
