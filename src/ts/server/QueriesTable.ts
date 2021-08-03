
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default class QueriesTable extends aSqliteTable {
    private pathsModel: ModelCtor<Model>;

    constructor(model: ModelCtor<Model>, pathsModel: ModelCtor<Model>) {
        super(model, ['protocol', 'PathId']);
        this.pathsModel = pathsModel;
    }

    private async getPathObj(path?: string): Promise<Model> {
        if (path === undefined) {
            throw new SqliteDatabaseError('missing path argument');
        }
        var pathObj = await this.pathsModel.findOne({
            where: {
                path: path
            }
        });
        if (pathObj == null) {
            throw new SqliteDatabaseError(`cannot find path "${path}"`);
        }
        return pathObj;
    }
    public async insert(vals: string[], path?: string): Promise<any> {
        if (vals[0]==null) {
            return;
        }
        this.validateValuesLength(vals);

        var pathObj = await this.getPathObj(path);
        return this.model.create({
            query: vals[0],
            PathId: pathObj.id
        }).catch((e) => {
            if (!this.isUniqueViolationError(e)) {
                throw e;
            }
            return null;
        });
    }
    public async bulkInsert(vals: string[][], path?: string): Promise<any> {
        var pathObj = await this.getPathObj(path);
        return this.model.bulkCreate(vals.flat().filter((v)=>v!=null).map((val) => {
            return {
                path: val,
                PathId: pathObj.id
            };
        })).catch((e) => {
            if (!this.isUniqueViolationError(e)) {
                throw e;
            }
            return null;
        });
    }
}
