
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';

export default class SrcDstTable extends aSqliteTable {

    constructor(model: ModelCtor<Model>) {
        super(model, ['src','dst']);
    }
}
