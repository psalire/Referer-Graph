
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';

export default class HostsTable extends aSqliteTable {

    constructor(model: ModelCtor<Model>) {
        super(model, ['host']);
    }

    public insert(vals: string[]): Promise<any> {
        super.validateValuesLength(vals);
        return this.model.create({
            host: vals[0],
        });
    }
    public bulkInsert(vals: string[][]): Promise<any> {
        return this.model.bulkCreate(vals.flat().map((val) => {
            return {host: val}
        }));
    }
}
