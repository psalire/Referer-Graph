
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';

export default class PathsTable extends aSqliteTable {
    private foreignModel?: ModelCtor<Model>;

    constructor(model: ModelCtor<Model>, foreignModel?: ModelCtor<Model>) {
        super(model, ['path']);
        if (foreignModel !== undefined) {
            this.foreignModel = foreignModel;
        }
    }

    public insert(vals: string[]): Promise<any> {
        super.validateValuesLength(vals);
        return this.model.create({
            path: vals[0]
        });
    }
    public bulkInsert(vals: string[][]): Promise<any> {
        return this.model.bulkCreate(vals.flat().map((val) => {
            return {path: val}
        }));
    }
}
