
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default class HostsTable extends aSqliteTable {
    private pathsModel: ModelCtor<Model>;

    constructor(model: ModelCtor<Model>, pathsModel: ModelCtor<Model>) {
        super(model, ['host']);
        this.pathsModel = pathsModel;
    }

    public insert(vals: string[], path?: string): Promise<any> {
        if (path===undefined) {
            throw new SqliteDatabaseError('HostsTable.insert(vals, path): expected path')
        }
        super.validateValuesLength(vals);
        return this.model.create(
            {
                host: vals[0],
                SrcPaths: [{
                    path: path
                }]
            },
            {
                include: [this.pathsModel]
            }
        );
    }
    public bulkInsert(vals: string[][]): Promise<any> {
        return this.model.bulkCreate(vals.flat().map((val) => {
            return {host: val}
        }));
    }
}
