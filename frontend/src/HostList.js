import React from 'react';
import { List, Datagrid, TextField, DeleteButton, TopToolbar, CreateButton } from 'react-admin';

const HostListActions = ({ basePath }) => (
    <TopToolbar>
        <CreateButton basePath={basePath} />
    </TopToolbar>
);

const HostList = (props) => (
    <List actions={<HostListActions />} {...props}>
        <Datagrid>
            <TextField source="id" />
            <TextField source="hostname" />
            <TextField source="ip" />
            <TextField source="type" />
            <DeleteButton />
        </Datagrid>
    </List>
);

export default HostList;
