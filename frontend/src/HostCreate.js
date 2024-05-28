import React from 'react';
import { Create, SimpleForm, TextInput } from 'react-admin';

const HostCreate = (props) => (
    <Create {...props}>
        <SimpleForm>
            <TextInput source="hostname" />
            <TextInput source="ip" />
            <TextInput source="type" />
        </SimpleForm>
    </Create>
);

export default HostCreate;