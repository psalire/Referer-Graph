
import { Model } from 'sequelize';

export default interface iDatabaseTable {
    sync(): Promise<any>;
    insert(vals: string[]): Promise<any>;
    bulkInsert(vals: string[][]): Promise<any>;
    selectAll(): Promise<Model[]>;
}
