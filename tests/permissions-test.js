const JwtAuthorizer = require('../index');

const gPermsJSON = '{"auth":{"service":0,"access":1,"createRole":2,"assignPermToRole":4,"assignRoleToUser":8},"credits":{"service":1,"giveOne":1,"giveMany":2},"videoCaptions":{"service":2,"canUpload":1},"users":{"service":3,"view":1,"edit":2}}';

const perm = new JwtAuthorizer.PermissionManager(gPermsJSON);

perm.addPermission(0, 1);
perm.addPermission(0, 4);
perm.addPermission(2, 4);

console.log(perm.toString());
console.log(perm.listPermissions());
