
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';

export default class HostsTable extends aSqliteTable {

    constructor(model: ModelCtor<Model>) {
        super(model, ['host']);
    }

    public async insert(vals: string[]): Promise<any> {
        this.validateValuesLength(vals);
        return this.model.create({
            host: vals[0],
        }).catch((e) => {
            if (!this.isUniqueViolationError(e, 1)) {
                throw e;
            }
            return null;
        });
    }
    public bulkInsert(vals: string[][]): Promise<any> {
        return this.model.bulkCreate(vals.flat().map((val) => {
            return {host: val};
        }));
    }
}
