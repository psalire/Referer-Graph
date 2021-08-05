
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default class SrcDstTable extends aSqliteTable {
    private pathsModel: ModelCtor<Model>;
    private hostsModel: ModelCtor<Model>;
    private protocolsModel: ModelCtor<Model>;

    constructor(
        model: ModelCtor<Model>, pathsModel: ModelCtor<Model>,
        hostsModel: ModelCtor<Model>, protocolsModel: ModelCtor<Model>
    ) {
        super(model, ['srcPathId','dstPathId']);
        this.pathsModel = pathsModel;
        this.hostsModel = hostsModel;
        this.protocolsModel = protocolsModel;
    }
    private async getProtocolObj(protocol?: string): Promise<Model> {
        if (protocol === undefined) {
            throw new SqliteDatabaseError('missing protocol argument');
        }
        var protocolObj = await this.protocolsModel.findOne({
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
        var hostObj = await this.hostsModel.findOne({
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
    private async getPathObj(path: string, host: string, protocol?: string): Promise<Model> {
        var pathParam = {
            path: path,
            HostId: (await this.getHostObj(host, protocol)).id
        }
        var pathObj = await this.pathsModel.findOne({
            where: pathParam
        });
        if (pathObj == null) {
            await this.pathsModel.create(pathParam);
            pathObj = await this.pathsModel.findOne({
                where: pathParam
            });
            if (pathObj == null) {
                throw new SqliteDatabaseError(
                    `SrcDstTable.getPathId(): Error creating path "${path}" for host="${host}"`
                );
            }
        }
        return pathObj;
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
        var srcHostObj = await this.getPathObj(vals[0], srcHost, srcProtocol);
        var dstHostObj = await this.getPathObj(vals[1], dstHost===undefined ? srcHost : dstHost, dstProtocol);
        return this.model.create({
            srcPathId: srcHostObj.id,
            dstPathId: dstHostObj.id
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
                'SrcDstTable.insert(vals, host, dstHost?): missing host argument'
            );
        }
        var dstHostStr = dstHost===undefined ? srcHost : dstHost;
        return this.model.bulkCreate(await Promise.all(
            vals.map(async (val) => {
                this.validateValuesLength(val);
                var srcHostObj = await this.getPathObj(val[0], srcHost, srcProtocol);
                var dstHostObj = await this.getPathObj(val[1], dstHostStr, dstProtocol);
                return {
                    srcPathId: srcHostObj.id,
                    dstPathId: dstHostObj.id
                };
            })
        ));
    }
}
