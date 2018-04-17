/* eslint-env node, mocha */
/* eslint-disable no-new */
/* eslint-disable no-unused-expressions */

const JwtAuthorizer = require('../index');
const chai = require('chai'); // eslint-disable-line
const expect = chai.expect; // eslint-disable-line

const gPermsJson = '{"auth":{"service":0,"access":1,"createRole":2,"assignPermToRole":4,"assignRoleToUser":8},"credits":{"service":1,"giveOne":1,"giveMany":2},"videoCaptions":{"service":2,"canUpload":1},"users":{"service":3,"view":1,"edit":2}}';
const gPermsJsonBadService = '{"auth":{"service":"abc","access":1,"createRole":2,"assignPermToRole":4,"assignRoleToUser":8},"credits":{"service":1,"giveOne":1,"giveMany":2},"videoCaptions":{"service":2,"canUpload":1},"users":{"service":3,"view":1,"edit":2}}';
const gPerms = JSON.parse(gPermsJson);

const setup = () => {
  const perm = new JwtAuthorizer.PermissionManager(gPermsJson);
  perm.addPermission(gPerms.auth.service, gPerms.auth.access);
  perm.addPermission(gPerms.auth.service, gPerms.auth.createRole);
  perm.addPermission(gPerms.auth.service, gPerms.auth.assignPermToRole);
  perm.addPermission(gPerms.auth.service, gPerms.auth.assignRoleToUser);
  perm.addPermission(gPerms.credits.service, gPerms.credits.giveOne);
  perm.addPermission(gPerms.credits.service, gPerms.credits.giveMany);
  perm.addPermission(gPerms.videoCaptions.service, gPerms.videoCaptions.canUpload);
  perm.addPermission(gPerms.users.service, gPerms.users.view);
  return perm;
};

const badConstructor = () => {
  new JwtAuthorizer.PermissionManager(gPermsJsonBadService);
};

describe('Constructor', () => {
  it('Fail for service error', () => {
    expect(badConstructor).to.throw('Service [auth] has no numeric service index');
  });
});

describe('Permission Tests', () => {
  let perm;
  beforeEach(() => {
    perm = setup();
  });

  it('Has done something', () => {
    expect(perm.toString()).to.be.a('string');
    expect(perm.listPermissions()).to.be.an('array').that.is.not.empty;
  });

  it('Has 8 permissions', () => {
    expect(perm.listPermissions()).to.have.lengthOf(8);
  });

  it('Has auth.access', () => {
    expect(perm.checkPermission(gPerms.auth.service, gPerms.auth.access)).to.equal(true);
  });
});

