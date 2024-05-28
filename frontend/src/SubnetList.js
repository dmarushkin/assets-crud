import React from 'react';
import { List, Datagrid, TextField, DeleteButton, TopToolbar, CreateButton } from 'react-admin';

const SubnetListActions = ({ basePath }) => (
    <TopToolbar>
        <CreateButton basePath={basePath} />
    </TopToolbar>
);

const SubnetList = (props) => (
    <List actions={<SubnetListActions />} {...props}>
        <Datagrid>
            <TextField source="id" />
            <TextField source="subnet" />
            <TextField source="env" />
            <TextField source="name" />
            <DeleteButton />
        </Datagrid>
    </List>
);

export default SubnetList;
