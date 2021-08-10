
import { Model } from 'sequelize';
import iDatabaseTable from './iDatabaseTable';
import iSQLTableFactory from './iSQLTableFactory';
import SqliteDatabase from './SqliteDatabase';
import aSqliteTable from './aSqliteTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default class SqliteTableFactory implements iSQLTableFactory {
    private db: SqliteDatabase;

    constructor(db: SqliteDatabase) {
        this.db = db;
    }

    private async getProtocolObj(protocol?: string): Promise<Model> {
        if (protocol === undefined) {
            throw new SqliteDatabaseError('missing protocol argument');
        }
        var protocolObj = await this.db.protocolsModel.findOne({
            where: {
                protocol: protocol
            }
        });
        if (protocolObj == null) {
            throw new SqliteDatabaseError(`cannot find protocol "${protocol}"`);
        }
        return protocolObj;
    }
    private async getHostObj(host?: string, protocol?: string): Promise<Model> {
        if (host === undefined) {
            throw new SqliteDatabaseError('missing host argument');
        }
        var protocolObj = await this.getProtocolObj(protocol);
        var hostObj = await this.db.hostsModel.findOne({
            where: {
                host: host,
                ProtocolId: protocolObj.id
            }
        });
        if (hostObj == null) {
            throw new SqliteDatabaseError(`cannot find host "${host}, protocol ${protocol}"`);
        }
        return hostObj;
    }
    private async getPathObj(path: string, host?: string, protocol?: string, createIfDNE?: boolean): Promise<Model> {
        if (host === undefined) {
            throw new SqliteDatabaseError('missing host argument');
        }
        if (protocol === undefined) {
            throw new SqliteDatabaseError('missing protocol argument');
        }
        var pathParam = {
            path: path,
            HostId: (await this.getHostObj(host, protocol)).id
        }
        var pathObj = await this.db.pathsModel.findOne({
            where: pathParam
        });
        if (pathObj == null) {
            if (createIfDNE==true) {
                await this.db.pathsModel.create(pathParam);
                pathObj = await this.db.pathsModel.findOne({
                    where: pathParam
                });
                if (pathObj == null) {
                    throw new SqliteDatabaseError(
                        `SrcDstTable.getPathId(): Error creating path "${path}" for host="${host}"`
                    );
                }
            }
            else {
                throw new SqliteDatabaseError(`cannot find path "${path}"`);
            }
        }
        return pathObj;
    }
    private async getMethodObj(method?: string): Promise<Model> {
        if (method === undefined) {
            throw new SqliteDatabaseError('missing method argument');
        }
        var methodObj = await this.db.methodsModel.findOne({
            where: {
                method: method
            }
        });
        if (methodObj == null) {
            throw new SqliteDatabaseError(`cannot find method "${method}"`);
        }
        return methodObj;
    }
    private async getHeadersObj(headers?: string): Promise<Model> {
        if (headers === undefined) {
            throw new SqliteDatabaseError('missing headers argument');
        }
        var headersObj = await this.db.headersModel.findOne({
            where: {
                headers: headers
            }
        });
        if (headersObj == null) {
            throw new SqliteDatabaseError(`cannot find header "${headers}"`);
        }
        return headersObj;
    }

    public createHostsTable(): iDatabaseTable {
        const parent = this;
        return new class extends aSqliteTable {
            constructor() {
                super(parent.db.hostsModel, ['host', 'ProtocolId']);
            }

            public async insert(vals: string[]): Promise<any> {
                this.validateValuesLength(vals);

                var protocolObj = await parent.getProtocolObj(vals[1]);
                return this.model.create({
                    host: vals[0],
                    ProtocolId: protocolObj.id
                }).catch((e) => {
                    if (!this.isUniqueViolationError(e)) {
                        throw e;
                    }
                    return null;
                });
            }
            public async bulkInsert(vals: string[][], protocol?: string): Promise<any> {
                var protocolObj = await parent.getProtocolObj(protocol);
                return this.model.bulkCreate(vals.flat().map((val) => {
                    return {
                        host: val,
                        ProtocolId: protocolObj.id
                    };
                }));
            }
        }();
    }
    public createPathsTable(): iDatabaseTable {
        const parent = this;
        return new class extends aSqliteTable {
            constructor() {
                super(parent.db.pathsModel, ['path', 'HostId']);
            }

            public async insert(vals: string[], protocol?: string): Promise<any> {
                this.validateValuesLength(vals);

                var hostObj = await parent.getHostObj(vals[1], protocol);
                return this.model.create({
                    path: vals[0],
                    HostId: hostObj.id
                }).catch((e) => {
                    if (!this.isUniqueViolationError(e)) {
                        throw e;
                    }
                    return null;
                });
            }
            public async bulkInsert(vals: string[][], host?: string, protocol?: string): Promise<any> {
                var hostObj = await parent.getHostObj(host, protocol);
                return this.model.bulkCreate(vals.flat().map((val) => {
                    return {
                        path: val,
                        HostId: hostObj.id
                    };
                })).catch((e) => {
                    if (!this.isUniqueViolationError(e)) {
                        throw e;
                    }
                    return null;
                });
            }
        }();
    }
    public createProtocolsTable(): iDatabaseTable {
        const parent = this;
        return new class extends aSqliteTable {
            constructor() {
                super(parent.db.protocolsModel, ['protocol']);
            }

            public async insert(vals: string[]): Promise<any> {
                this.validateValuesLength(vals);
                return this.model.create({
                    protocol: vals[0],
                }).catch((e) => {
                    if (!this.isUniqueViolationError(e, undefined, 1)) {
                        throw e;
                    }
                    return null;
                });
            }
            public bulkInsert(vals: string[][]): Promise<any> {
                return this.model.bulkCreate(vals.flat().map((val) => {
                    return {protocol: val};
                }));
            }
        }();
    }
    public createQueriesTable(): iDatabaseTable {
        const parent = this;
        return new class extends aSqliteTable {
            constructor() {
                super(parent.db.queriesModel, ['protocol', 'PathId']);
            }

            public async insert(vals: string[], protocol?: string, host?: string): Promise<any> {
                this.validateValuesLength(vals);

                var pathObj = await parent.getPathObj(vals[1], host, protocol, false);
                return this.model.create({
                    query: vals[0],
                    PathId: pathObj.id
                }).catch((e) => {
                    if (!this.isUniqueViolationError(e)) {
                        throw e;
                    }
                    return null;
                });
            }
            public async bulkInsert(vals: string[][], path?: string, protocol?: string, host?: string): Promise<any> {
                if (path===undefined) {
                    throw new SqliteDatabaseError('missing path argument');
                }
                var pathObj = await parent.getPathObj(path, host, protocol, false);
                return this.model.bulkCreate(vals.flat().map((val) => {
                    return {
                        path: val,
                        PathId: pathObj.id
                    };
                })).catch((e) => {
                    if (!this.isUniqueViolationError(e)) {
                        throw e;
                    }
                    return null;
                });
            }
        }();
    }
    public createMethodsTable(): iDatabaseTable {
        const parent = this;
        return new class extends aSqliteTable {
            constructor() {
                super(parent.db.methodsModel, ['method']);
            }

            public async insert(vals: string[]): Promise<any> {
                this.validateValuesLength(vals);
                return this.model.create({
                    method: vals[0]
                }).catch((e) => {
                    if (!this.isUniqueViolationError(e, undefined, 1)) {
                        throw e;
                    }
                    return null;
                });
            }
            public bulkInsert(vals: string[][]): Promise<any> {
                return this.model.bulkCreate(vals.flat().map((val) => {
                    return {method: val};
                }));
            }
        }();
    }
    public createHeadersTable(): iDatabaseTable {
        const parent = this;
        return new class extends aSqliteTable {
            constructor() {
                super(parent.db.headersModel, ['headers']);
            }

            public async insert(vals: string[]): Promise<any> {
                this.validateValuesLength(vals);
                return this.model.create({
                    headers: vals[0],
                }).catch((e) => {
                    if (!this.isUniqueViolationError(e, undefined, 1)) {
                        throw e;
                    }
                    return null;
                });
            }
            public bulkInsert(vals: string[][]): Promise<any> {
                return this.model.bulkCreate(vals.flat().map((val) => {
                    return {headers: val};
                }));
            }
        }();
    }
    public createSrcDstsTable(): iDatabaseTable {
        const parent = this;
        return new class extends aSqliteTable {
            constructor() {
                super(parent.db.srcDstModel, ['srcPathId','dstPathId','methodId','requestHeadersId','responseHeadersId']);
            }

            public async insert(
                vals: string[], srcProtocol?: string, dstProtocol?: string,
                srcHost?: string, dstHost?: string
            ): Promise<any> {
                if (srcHost === undefined) {
                    throw new SqliteDatabaseError(
                        'SrcDstTable.insert(): missing host argument'
                    );
                }
                this.validateValuesLength(vals);
                var srcHostObj = await parent.getPathObj(vals[0], srcHost, srcProtocol, true);
                var dstHostObj = await parent.getPathObj(vals[1], dstHost===undefined ? srcHost : dstHost, dstProtocol, true);
                var methodObj = await parent.getMethodObj(vals[2]);
                var srcHeadersObj = await parent.getHeadersObj(vals[3]);
                var dstHeadersObj = await parent.getHeadersObj(vals[4]);
                return this.model.create({
                    srcPathId: srcHostObj.id,
                    dstPathId: dstHostObj.id,
                    methodId: methodObj.id,
                    requestHeadersId: srcHeadersObj.id,
                    responseHeadersId: dstHeadersObj.id
                }).catch((e) => {
                    if (!this.isUniqueViolationError(e)) {
                        throw e;
                    }
                    return null;
                });
            }
            public async bulkInsert(
                vals: string[][], srcProtocol?: string, dstProtocol?: string,
                srcHost?: string, dstHost?: string
            ): Promise<any> {
                if (srcHost === undefined) {
                    throw new SqliteDatabaseError(
                        'SrcDstTable.insert(): missing host argument'
                    );
                }
                var dstHostStr = dstHost===undefined ? srcHost : dstHost;
                return this.model.bulkCreate(await Promise.all(
                    vals.map(async (val) => {
                        this.validateValuesLength(val);
                        var srcHostObj = await parent.getPathObj(val[0], srcHost, srcProtocol, true);
                        var dstHostObj = await parent.getPathObj(val[1], dstHostStr, dstProtocol, true);
                        var methodObj = await parent.getMethodObj(val[2]);
                        var headersObj = await parent.getHeadersObj(vals[3]);
                        return {
                            srcPathId: srcHostObj.id,
                            dstPathId: dstHostObj.id,
                            methodId: methodObj.id,
                            headersId: headersObj.id,
                        };
                    })
                ));
            }
        }();
    }
}
