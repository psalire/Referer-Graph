
import { Model, ModelCtor } from 'sequelize';
import aSqliteTable from './aSqliteTable';
import SqliteDatabaseError from './SqliteDatabaseError';

export default class PathsTable extends aSqliteTable {
    private hostsModel: ModelCtor<Model>;
    private protocolsModel: ModelCtor<Model>;

    constructor(model: ModelCtor<Model>, hostsModel: ModelCtor<Model>, protocolsModel: ModelCtor<Model>) {
        super(model, ['path', 'HostId']);
        this.hostsModel = hostsModel;
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
    private async getHostObj(host?: string, protocol?: string): Promise<Model> {
        if (host === undefined) {
            throw new SqliteDatabaseError('missing host argument');
        }
        var protocolObj = await this.getProtocolObj(protocol);
        var hostObj = await this.hostsModel.findOne({
            where: {
                host: host,
                ProtocolId: protocolObj.id
            }
        });
        if (hostObj == null) {
            throw new SqliteDatabaseError(`cannot find host "${host}, protocol ${protocol}"`);
        }
        return hostObj;
    }
    public async insert(vals: string[], protocol?: string): Promise<any> {
        this.validateValuesLength(vals);

        var hostObj = await this.getHostObj(vals[1], protocol);
        return this.model.create({
            path: vals[0],
            HostId: hostObj.id
        }).catch((e) => {
            if (!this.isUniqueViolationError(e)) {
                throw e;
            }
            return null;
        });
    }
    public async bulkInsert(vals: string[][], host?: string, protocol?: string): Promise<any> {
        var hostObj = await this.getHostObj(host, protocol);
        return this.model.bulkCreate(vals.flat().map((val) => {
            return {
                path: val,
                HostId: hostObj.id
            };
        })).catch((e) => {
            if (!this.isUniqueViolationError(e)) {
                throw e;
            }
            return null;
        });
    }
}
