
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default class SrcDstTable extends aSqliteTable {
    private pathsModel: ModelCtor<Model>;
    private hostsModel: ModelCtor<Model>;

    constructor(model: ModelCtor<Model>, pathsModel?: ModelCtor<Model>, hostsModel?: ModelCtor<Model>) {
        if (pathsModel === undefined || hostsModel === undefined) {
            throw new SqliteDatabaseError(
                `SrcDstTable(model, pathsModel, hostModel): need 3 parameters, got ${
                    1 + Number(pathsModel!==undefined) + Number(hostsModel!==undefined)
                }`
            );
        }
        super(model, ['src','dst']);
        this.pathsModel = pathsModel;
        this.hostsModel = hostsModel;
    }
    private async getPathId(path: string, host: string): Promise<number> {
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
        return pathObj.id;
    }
    public async insert(vals: string[], srcHost?: string, dstHost?: string): Promise<any> {
        if (srcHost === undefined) {
            throw new SqliteDatabaseError(
                'SrcDstTable.insert(vals, host, dstHost?): missing host argument'
            );
        }
        let dstHostname = dstHost===undefined ? srcHost : dstHost;
        super.validateValuesLength(vals);
        return this.model.create({
            src: await this.getPathId(vals[0], srcHost),
            dst: await this.getPathId(vals[1], dstHostname)
        });
    }
}
