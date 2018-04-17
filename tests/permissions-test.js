/* eslint-env node, mocha */

const JwtAuthorizer = require('../index');
const chai = require('chai'); // eslint-disable-line
const describe = chai.describe(); // eslint-disable-line
const expect = chai.expect(); // eslint-disable-line

const gPermsJson = '{"auth":{"service":0,"access":1,"createRole":2,"assignPermToRole":4,"assignRoleToUser":8},"credits":{"service":1,"giveOne":1,"giveMany":2},"videoCaptions":{"service":2,"canUpload":1},"users":{"service":3,"view":1,"edit":2}}';
const gPermsJsonBadService = '{"auth":{"service":"abc","access":1,"createRole":2,"assignPermToRole":4,"assignRoleToUser":8},"credits":{"service":1,"giveOne":1,"giveMany":2},"videoCaptions":{"service":2,"canUpload":1},"users":{"service":3,"view":1,"edit":2}}';
const gPerms = JSON.parse(gPermsJson);

const perm = new JwtAuthorizer.PermissionManager(gPermsJson);

perm.addPermission(gPerms.auth.service, gPerms.auth.access);
perm.addPermission(gPerms.auth.service, gPerms.auth.createRole);
perm.addPermission(gPerms.auth.service, gPerms.auth.assignPermToRole);
perm.addPermission(gPerms.auth.service, gPerms.auth.assignRoleToUser);
perm.addPermission(gPerms.credits.service, gPerms.credits.giveOne);
perm.addPermission(gPerms.credits.service, gPerms.credits.giveMany);
perm.addPermission(gPerms.videoCaptions.service, gPerms.videoCaptions.canUpload);
perm.addPermission(gPerms.users.service, gPerms.users.canView);

describe('Bad JSON', () => {
  it('Fail for service error', () => {
    expect(new JwtAuthorizer.PermissionManager(gPermsJsonBadService).to.throw(new Error('Service [auth] has no numeric service index')));
  });
});

console.log(perm.toString());
console.log(perm.listPermissions());
