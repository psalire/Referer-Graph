
import { Model, ModelCtor } from 'sequelize';
import aDatabaseTable from './aSqliteTable';

export default class PathsTable extends aDatabaseTable {

    constructor(model: ModelCtor<Model>) {
        super(model, ['path']);
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
