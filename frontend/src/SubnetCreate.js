import React from 'react';
import { Create, SimpleForm, TextInput } from 'react-admin';

const SubnetCreate = (props) => (
    <Create {...props}>
        <SimpleForm>
            <TextInput source="subnet" />
            <TextInput source="env" />
            <TextInput source="name" />
        </SimpleForm>
    </Create>
);

export default SubnetCreate;