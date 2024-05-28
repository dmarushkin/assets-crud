import React from 'react';
import { Admin, Resource } from 'react-admin';
import customDataProvider from './customDataProvider';
import authProvider from './authProvider';
import HostList from './HostList';
import HostCreate from './HostCreate';
import SubnetList from './SubnetList';
import SubnetCreate from './SubnetCreate';
import DangerousCVEList from './DangerousCVEList';
import DangerousCVECreate from './DangerousCVECreate';


const App = () => (
    <Admin dataProvider={customDataProvider} authProvider={authProvider}>
        <Resource name="hosts" list={HostList} create={HostCreate} />
        <Resource name="subnets" list={SubnetList} create={SubnetCreate} />
        <Resource name="dangerous-cves" list={DangerousCVEList} create={DangerousCVECreate} />
    </Admin>
);

export default App;