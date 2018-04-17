const JwtAuthorizer = require('../index');

const gPermsJSON = '{"auth":{"service":0,"access":1,"createRole":2,"assignPermToRole":4,"assignRoleToUser":8},"credits":{"service":1,"giveOne":1,"giveMany":2},"videoCaptions":{"service":2,"canUpload":1},"users":{"service":3,"view":1,"edit":2}}';
const gPerms = JSON.parse(gPermsJSON);

const perm = new JwtAuthorizer.PermissionManager(gPermsJSON);

perm.addPermission(gPerms.auth.service, gPerms.auth.access);
perm.addPermission(gPerms.auth.service, gPerms.auth.createRole);
perm.addPermission(gPerms.auth.service, gPerms.auth.assignPermToRole);
perm.addPermission(gPerms.auth.service, gPerms.auth.assignRoleToUser);
perm.addPermission(gPerms.credits.service, gPerms.credits.giveOne);
perm.addPermission(gPerms.credits.service, gPerms.credits.giveMany);
perm.addPermission(gPerms.videoCaptions.service, gPerms.videoCaptions.canUpload);
perm.addPermission(gPerms.users.service, gPerms.users.canView);

console.log(perm.toString());
console.log(perm.listPermissions());
