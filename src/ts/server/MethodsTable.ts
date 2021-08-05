
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';

export default class MethodsTable extends aSqliteTable {

    constructor(model: ModelCtor<Model>) {
        super(model, ['method']);
    }

    public async insert(vals: string[]): Promise<any> {
        this.validateValuesLength(vals);
        return this.model.create({
            method: vals[0],
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
}
