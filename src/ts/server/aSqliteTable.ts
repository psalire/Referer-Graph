
import { Model, ModelCtor, ValidationError, UniqueConstraintError, OrderItem } from 'sequelize';
import iDatabaseTable from './iDatabaseTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default abstract class aSqliteTable implements iDatabaseTable {
    protected model: ModelCtor<Model>;
    protected columns: string[];

    constructor(model: ModelCtor<Model>, columns: string[]) {
        this.model = model;
        this.columns = columns;
    }

    protected isUniqueViolationError(e: Error, vals?: string[], expectedLength?: number) {
        if (e instanceof UniqueConstraintError) {
            return true;
        }
        if (e instanceof ValidationError) {
            if (e.errors.length==expectedLength &&
                e.errors[0].type == 'unique violation' &&
                e.errors[0].message == 'host must be unique') {
                return true;
            }
            for (let err of e.errors) {
                console.error(err);
            }
        }
        if (vals !== undefined) {
            console.error('With vals: ');
            console.error(vals);
        }
        return false;
    }
    protected validateValuesLength(vals: string[]): void {
        if (vals.length != this.columns.length) {
            throw new SqliteDatabaseError(
                `Expected length ${this.columns.length}. Got ${vals.length}: ${JSON.stringify(vals)}`
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

    public selectAll(where?: object, order?: OrderItem[]): Promise<Model[]> {
        return this.model.findAll({
            attributes: this.columns,
            where: where,
            order: order
        });
    }
    public selectOne(where: object): Promise<Model|null> {
        return this.model.findOne({
            where: where
        });
    }
    public selectByPk(pk: number): Promise<Model|null> {
        return this.model.findByPk(pk);
    }
}
