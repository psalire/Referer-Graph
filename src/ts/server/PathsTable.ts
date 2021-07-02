
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default class PathsTable extends aSqliteTable {
    private hostsModel: ModelCtor<Model>;

    constructor(model: ModelCtor<Model>, hostsModel: ModelCtor<Model>) {
        super(model, ['path', 'HostId']);
        this.hostsModel = hostsModel;
    }
    public async insert(vals: string[], host?: string): Promise<any> {
        if (host === undefined) {
            throw new SqliteDatabaseError('missing host argument');
        }
        super.validateValuesLength(vals);

        var hostObj = await this.hostsModel.findOne({
            where: {
                host: host
            }
        });
        if (hostObj == null) {
            throw new SqliteDatabaseError(`cannot find host "${host}"`);
        }
        return this.model.create({
            path: vals[0],
            HostId: hostObj.id
        });
    }
    public async bulkInsert(vals: string[][], host?: string): Promise<any> {
        if (host === undefined) {
            throw new SqliteDatabaseError('missing host argument');
        }

        var hostObj = await this.hostsModel.findOne({
            where: {
                host: host
            }
        });

        return this.model.bulkCreate(vals.flat().map((val) => {
            return {path: val};
        })).then((createdObjs) => {
            for (let obj of createdObjs) {
                obj.setHost(hostObj);
            }
            return createdObjs;
        });
    }
}
