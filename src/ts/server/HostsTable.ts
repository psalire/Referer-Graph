
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default class HostsTable extends aSqliteTable {
    private protocolsModel: ModelCtor<Model>;

    constructor(model: ModelCtor<Model>, protocolsModel: ModelCtor<Model>) {
        super(model, ['host', 'ProtocolId']);
        this.protocolsModel = protocolsModel;
    }

    private async getProtocolObj(protocol?: string): Promise<Model> {
        if (protocol === undefined) {
            throw new SqliteDatabaseError('missing protocol argument');
        }
        var protocolObj = await this.protocolsModel.findOne({
            where: {
                protocol: protocol
            }
        });
        if (protocolObj == null) {
            throw new SqliteDatabaseError(`cannot find protocol "${protocol}"`);
        }
        return protocolObj;
    }
    public async insert(vals: string[]): Promise<any> {
        this.validateValuesLength(vals);

        var protocolObj = await this.getProtocolObj(vals[1]);
        return this.model.create({
            host: vals[0],
            ProtocolId: protocolObj.id
        }).catch((e) => {
            if (!this.isUniqueViolationError(e, undefined, 1)) {
                throw e;
            }
            return null;
        });
    }
    public async bulkInsert(vals: string[][], protocol?: string): Promise<any> {
        var protocolObj = await this.getProtocolObj(protocol);
        return this.model.bulkCreate(vals.flat().map((val) => {
            return {
                host: val,
                ProtocolId: protocolObj.id
            };
        }));
    }
}
