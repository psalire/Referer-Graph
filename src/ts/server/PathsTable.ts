
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default class PathsTable extends aSqliteTable {
    private hostsModel: ModelCtor<Model>;

    constructor(model: ModelCtor<Model>, hostsModel: ModelCtor<Model>) {
        super(model, ['path', 'HostId']);
        this.hostsModel = hostsModel;
    }

    private async getHostObj(host?: string): Promise<Model> {
        if (host === undefined) {
            throw new SqliteDatabaseError('missing host argument');
        }
        var hostObj = await this.hostsModel.findOne({
            where: {
                host: host
            }
        });
        if (hostObj == null) {
            throw new SqliteDatabaseError(`cannot find host "${host}"`);
        }
        return hostObj;
    }
    public async insert(vals: string[], host?: string): Promise<any> {
        super.validateValuesLength(vals);

        var hostObj = await this.getHostObj(host);
        var count = await this.model.count({
            where: {
                path: vals[0],
                HostId: hostObj.id
            }
        });
        if (count != 0) {
            return new Promise((resolve, _) => {
                console.log('duplicate path');
                resolve(null);
            });
        }
        return this.model.create({
            path: vals[0],
            HostId: hostObj.id
        });
    }
    public async bulkInsert(vals: string[][], host?: string): Promise<any> {
        var hostObj = await this.getHostObj(host);
        return this.model.bulkCreate(vals.flat().map((val) => {
            return {
                path: val,
                HostId: hostObj.id
            };
        }));
    }
}
