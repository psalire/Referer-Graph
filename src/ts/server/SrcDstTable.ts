
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
        var hostObj = await this.hostsModel.findOne({
            where: {
                host: host
            }
        });
        if (hostObj == null) {
            throw new SqliteDatabaseError(
                `SrcDstTable.getPathId(): Can't find in Hosts table host="${host}"`
            );
        }
        var pathObj = await this.pathsModel.findOne({
            where: {
                path: path,
                hostId: hostObj.id
            }
        });
        if (pathObj == null) {
            throw new SqliteDatabaseError(
                `SrcDstTable.getPathId(): Can't find in Paths table path="${path}" && host="${host}"`
            );
        }
        return pathObj;
    }
    public async insert(vals: string[], srcHost?: string, dstHost?: string): Promise<any> {
        if (srcHost === undefined) {
            throw new SqliteDatabaseError(
                'SrcDstTable.insert(vals, host, dstHost?): missing host argument'
            );
        }
        super.validateValuesLength(vals);
        var srcHostObj = await this.getPathObj(vals[0], srcHost);
        var dstHostObj = await this.getPathObj(vals[1], dstHost===undefined ? srcHost : dstHost);
        return this.model.create({
            srcPathId: srcHostObj.id,
            dstPathId: dstHostObj.id
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
                super.validateValuesLength(val);
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
