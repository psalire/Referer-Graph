
import { Model, ModelCtor, ValidationError } from 'sequelize';
import aSqliteTable from './aSqliteTable';

export default class HostsTable extends aSqliteTable {

    constructor(model: ModelCtor<Model>) {
        super(model, ['host']);
    }

    private isUniqueViolationError(e: Error) {
        return (e instanceof ValidationError) &&
            e.errors.length==1 &&
            e.errors[0].type == 'unique violation' &&
            e.errors[0].message == 'host must be unique';
    }

    public async insert(vals: string[]): Promise<any> {
        super.validateValuesLength(vals);
        return this.model.create({
            host: vals[0],
        }).catch((e) => {
            if (!this.isUniqueViolationError(e)) {
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
