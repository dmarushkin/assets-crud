import React from 'react';
import { Create, SimpleForm, TextInput } from 'react-admin';

const DangerousCVECreate = (props) => (
    <Create {...props}>
        <SimpleForm>
            <TextInput source="cve_id" />
            <TextInput source="comment" />
        </SimpleForm>
    </Create>
);

export default DangerousCVECreate;