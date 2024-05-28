import React from 'react';
import { List, Datagrid, TextField, DeleteButton, TopToolbar, CreateButton } from 'react-admin';

const DangerousCVEListActions = ({ basePath }) => (
    <TopToolbar>
        <CreateButton basePath={basePath} />
    </TopToolbar>
);

const DangerousCVEList = (props) => (
    <List actions={<DangerousCVEListActions />} {...props}>
        <Datagrid>
            <TextField source="id" />
            <TextField source="cve_id" />
            <TextField source="comment" />
            <DeleteButton />
        </Datagrid>
    </List>
);

export default DangerousCVEList;