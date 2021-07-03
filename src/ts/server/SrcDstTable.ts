
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default class SrcDstTable extends aSqliteTable {
    private pathsModel: ModelCtor<Model>;
    private hostsModel: ModelCtor<Model>;

    constructor(model: ModelCtor<Model>, pathsModel: ModelCtor<Model>, hostsModel: ModelCtor<Model>) {
        super(model, ['srcPathId','dstPathId']);
        this.pathsModel = pathsModel;
        this.hostsModel = hostsModel;
    }
    private async getPathObj(path: string, host: string): Promise<Model> {
        var hostParam = {
            host: host
        };
        var hostObj = await this.hostsModel.findOne({
            where: hostParam
        });
        if (hostObj == null) {
            await this.hostsModel.create(hostParam);
            hostObj = await this.hostsModel.findOne({
                where: hostParam
            });
            if (hostObj == null) {
                throw new SqliteDatabaseError(
                    `SrcDstTable.getPathId(): Error creating host "${host}"`
                );
            }
        }
        var pathParam = {
            path: path,
            HostId: hostObj.id
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

    public async insert(vals: string[], srcHost?: string, dstHost?: string): Promise<any> {
        if (srcHost === undefined) {
            throw new SqliteDatabaseError(
                'SrcDstTable.insert(vals, host, dstHost?): missing host argument'
            );
        }
        this.validateValuesLength(vals);
        var srcHostObj = await this.getPathObj(vals[0], srcHost);
        var dstHostObj = await this.getPathObj(vals[1], dstHost===undefined ? srcHost : dstHost);
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
    public async bulkInsert(vals: string[][], srcHost?: string, dstHost?: string): Promise<any> {
        if (srcHost === undefined) {
            throw new SqliteDatabaseError(
                'SrcDstTable.insert(vals, host, dstHost?): missing host argument'
            );
        }
        var dstHostStr = dstHost===undefined ? srcHost : dstHost;
        return this.model.bulkCreate(await Promise.all(
            vals.map(async (val) => {
                this.validateValuesLength(val);
                var srcHostObj = await this.getPathObj(val[0], srcHost);
                var dstHostObj = await this.getPathObj(val[1], dstHostStr);
                return {
                    srcPathId: srcHostObj.id,
                    dstPathId: dstHostObj.id
                };
            })
        ));
    }
}
