
import { Model, ModelCtor } from 'sequelize';
import aDatabaseTable from './aDatabaseTable';

export default class HostTable extends aDatabaseTable {

    constructor(model: ModelCtor<Model>) {
        super(model, ['host']);
    }
}
