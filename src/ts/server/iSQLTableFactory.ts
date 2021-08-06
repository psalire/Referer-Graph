
import iDatabaseTable from './iDatabaseTable';

export default interface iSQLTableFactory {
    createHostsTable(): iDatabaseTable;
    createPathsTable(): iDatabaseTable;
    createProtocolsTable(): iDatabaseTable;
    createQueriesTable(): iDatabaseTable;
    createMethodsTable(): iDatabaseTable;
    createSrcDstsTable(): iDatabaseTable;
}
