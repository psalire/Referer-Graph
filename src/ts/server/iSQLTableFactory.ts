
import iDatabaseTable from './iDatabaseTable';

export default interface iSQLTableFactory {
    createHostsTable(): iDatabaseTable;
    createPathsTable(): iDatabaseTable;
    createProtocolsTable(): iDatabaseTable;
    createQueriesTable(): iDatabaseTable;
    createMethodsTable(): iDatabaseTable;
    createHeadersTable(): iDatabaseTable;
    createSrcDstsTable(): iDatabaseTable;
}
