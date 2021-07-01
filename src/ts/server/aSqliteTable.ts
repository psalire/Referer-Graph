
import { Model, ModelCtor } from 'sequelize';
import iDatabaseTable from './iDatabaseTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default abstract class aSqliteTable implements iDatabaseTable {
    protected model: ModelCtor<Model>;
    protected columns: string[];

    constructor(model: ModelCtor<Model>, columns: string[]) {
        this.model = model;
        this.columns = columns;
    }

    protected validateValuesLength(vals: string[]): void {
        if (vals.length != this.columns.length) {
            new SqliteDatabaseError(
                `Expected length ${this.columns.length}. Got ${vals.length}`
            );
        }
    }
    private mapColumnsToValues(vals: string[]): object {
        this.validateValuesLength(vals);
        return this.columns.reduce(
            (obj: {[key: string]: any}, col: string, i: number) => {
                obj[col] = vals[i];
                return obj;
            }, {}
        );
    }

    public sync(): Promise<any> {
        return this.model.sync();
    }
    public insert(vals: string[]): Promise<any> {
        return this.model.create(this.mapColumnsToValues(vals));
    }
    public bulkInsert(vals: string[][]): Promise<any> {
        return this.model.bulkCreate(vals.map(val => {
            return this.mapColumnsToValues(val);
        }));
    }
    public selectAll(): Promise<Model[]> {
        return this.model.findAll({
            attributes: this.columns
        });
    }
}
