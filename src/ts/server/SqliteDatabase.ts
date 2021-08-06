
import { Sequelize, DataTypes, Model, ModelCtor } from 'sequelize';
import * as path from 'path';
import ProtocolsTable from './ProtocolsTable';
import HostsTable from './HostsTable';
import PathsTable from './PathsTable';
import QueriesTable from './QueriesTable';
import MethodsTable from './MethodsTable';
import SrcDstTable from './SrcDstTable';
import iDatabaseTable from './iDatabaseTable';
import SqliteTableFactory from './SqliteTableFactory';

export default class SqliteDatabase {
    private sequelize: Sequelize;
    private filepath: string;
    public protocols: iDatabaseTable;
    public hosts: iDatabaseTable;
    public paths: iDatabaseTable;
    public queries: iDatabaseTable;
    public methods: iDatabaseTable;
    public srcDsts: iDatabaseTable;
    public protocolsModel: ModelCtor<Model>;
    public hostsModel: ModelCtor<Model>;
    public pathsModel: ModelCtor<Model>;
    public queriesModel: ModelCtor<Model>;
    public methodsModel: ModelCtor<Model>;
    public srcDstModel: ModelCtor<Model>;

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

        this.protocolsModel = this.sequelize.define(
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
        this.hostsModel = this.sequelize.define(
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
                        model: this.protocolsModel,
                        key: 'id'
                    }
                }
            },
            {
                timestamps: false,
                createdAt: false
            }
        );
        this.pathsModel = this.sequelize.define(
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
                        model: this.hostsModel,
                        key: 'id'
                    }
                }
            },
            {
                timestamps: false,
                createdAt: false
            }
        );
        this.queriesModel = this.sequelize.define(
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
                        model: this.pathsModel,
                        key: 'id'
                    }
                }
            },
            {
                timestamps: false,
                createdAt: false
            }
        );
        this.methodsModel = this.sequelize.define(
            'Method',
            {
                method: {
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
        this.srcDstModel = this.sequelize.define(
            'SrcDst',
            {
                srcPathId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    unique: 'srcDstComposite',
                    references: {
                        model: this.pathsModel,
                        key: 'id'
                    }
                },
                dstPathId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    unique: 'srcDstComposite',
                    references: {
                        model: this.pathsModel,
                        key: 'id'
                    }
                },
                methodId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    unique: 'srcDstComposite',
                    references: {
                        model: this.methodsModel,
                        key: 'id'
                    }
                }
            },
            {
                timestamps: false,
                createdAt: false
            }
        );

        this.hostsModel.hasMany(this.pathsModel, {
            foreignKey: {
                allowNull: false
            }
        });
        this.pathsModel.belongsTo(this.hostsModel);
        this.pathsModel.hasMany(this.srcDstModel, {
            as: 'src',
            foreignKey: {
                name: 'srcPathId',
                allowNull: false
            }
        });
        this.pathsModel.hasMany(this.srcDstModel, {
            as: 'dst',
            foreignKey: {
                name: 'dstPathId',
                allowNull: false
            }
        });
        this.pathsModel.hasMany(this.queriesModel, {
            foreignKey: {
                allowNull: false
            }
        });

        var tableFactory = new SqliteTableFactory(this);
        this.protocols = tableFactory.createProtocolsTable();
        this.hosts = tableFactory.createHostsTable();
        this.paths = tableFactory.createPathsTable();
        this.queries = tableFactory.createQueriesTable();
        this.methods = tableFactory.createMethodsTable();
        this.srcDsts = tableFactory.createSrcDstsTable();

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
