/* eslint-env node, mocha */
/* eslint-disable no-new */
/* eslint-disable no-unused-expressions */

const JwtAuthorizer = require('../index');
const chai = require('chai'); // eslint-disable-line
const expect = chai.expect; // eslint-disable-line

const gPermsJson = `{
  "auth": {
    "service": 0,
    "access": 1,
    "createRole": 2,
    "assignPermToRole": 4,
    "assignRoleToUser": 8
  },
  "credits": {
    "service": 1,
    "giveOne": 1,
    "giveMany": 2
  },
  "videoCaptions": {
    "service": 2,
    "canUpload": 1
  },
  "users": {
    "service": 3,
    "view": 1,
    "edit": 2
  }
}`;

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

const noConfigFile = () => {
  new JwtAuthorizer.PermissionManager();
};

describe('Permission Manager', () => {
  describe('Constructor', () => {
    it('Fail for service has no numeric service index', () => {
      const gPermsJsonBadService = `{
        "auth": {
          "service": "abc",
          "access": 1,
          "createRole": 2,
          "assignPermToRole": 4,
          "assignRoleToUser": 8
        },
        "credits": {
          "service": 1,
          "giveOne": 1,
          "giveMany": 2
        }
      }`;

      const badConstructor = () => {
        new JwtAuthorizer.PermissionManager(gPermsJsonBadService);
      };

      expect(badConstructor).to.throw('Service [auth] has no numeric service index');
    });

    it('Fail for service has an index greater than the number of services', () => {
      const gPermsJsonBadService = `{
        "auth": {
          "service": 10,
          "access": 1,
          "createRole": 2,
          "assignPermToRole": 4,
          "assignRoleToUser": 8
        },
        "credits": {
          "service": 1,
          "giveOne": 1,
          "giveMany": 2
        }
      }`;

      const badConstructor = () => {
        new JwtAuthorizer.PermissionManager(gPermsJsonBadService);
      };

      expect(badConstructor).to.throw('Service [auth] has an index greater than the number of services');
    });

    it('Fail for service index exists twice', () => {
      const gPermsJsonBadService = `{
        "auth": {
          "service": 1,
          "access": 1,
          "createRole": 2,
          "assignPermToRole": 4,
          "assignRoleToUser": 8
        },
        "credits": {
          "service": 1,
          "giveOne": 1,
          "giveMany": 2
        }
      }`;

      const badConstructor = () => {
        new JwtAuthorizer.PermissionManager(gPermsJsonBadService);
      };

      expect(badConstructor).to.throw('Service index [1] exists twice (extra time in [credits])');
    });

    it('Fail for service value is not base2', () => {
      const gPermsJsonBadService = `{
        "auth": {
          "service": 0,
          "access": 3,
          "createRole": 2,
          "assignPermToRole": 4,
          "assignRoleToUser": 8
        },
        "credits": {
          "service": 1,
          "giveOne": 1,
          "giveMany": 2
        }
      }`;

      const badConstructor = () => {
        new JwtAuthorizer.PermissionManager(gPermsJsonBadService);
      };

      expect(badConstructor).to.throw('Value [3] is not Base2');
    });

    it('Fail for service value exists twice', () => {
      const gPermsJsonBadService = `{
        "auth": {
          "service": 0,
          "access": 1,
          "createRole": 1,
          "assignPermToRole": 4,
          "assignRoleToUser": 8
        },
        "credits": {
          "service": 1,
          "giveOne": 1,
          "giveMany": 2
        }
      }`;

      const badConstructor = () => {
        new JwtAuthorizer.PermissionManager(gPermsJsonBadService);
      };

      expect(badConstructor).to.throw('Value [1] exists twice');
    });

    it('Fail for no config file supplied', () => {
      expect(noConfigFile).to.throw('No config file supplied');
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

    it('Fail for addPermission', () => {
      const test = () => {
        perm.addPermission(4, 3);
      };

      expect(test).to.throw('Service doesn\'t match global permissions object');
    });

    it('Fail for removePermission', () => {
      const test = () => {
        perm.removePermission(4, 3);
      };

      expect(test).to.throw('Service doesn\'t match global permissions object');
    });

    it('Modifying the existing perms by adding users.edit', () => {
      const test = new JwtAuthorizer.PermissionManager(gPermsJson, perm.toString());
      test.addPermission(gPerms.users.service, gPerms.users.edit);

      expect(test.listPermissions()).to.have.lengthOf(9);
      expect(test.checkPermission(gPerms.users.service, gPerms.users.view)).to.equal(true);
      expect(test.checkPermission(gPerms.users.service, gPerms.users.edit)).to.equal(true);
      expect(test.checkPermission(gPerms.auth.service, gPerms.auth.access)).to.equal(true);
    });

    it('Modifying the existing perms by removing users.view', () => {
      const test = new JwtAuthorizer.PermissionManager(gPermsJson, perm.toString());
      test.removePermission(gPerms.users.service, gPerms.users.view);

      expect(test.listPermissions()).to.have.lengthOf(7);
      expect(test.checkPermission(gPerms.users.service, gPerms.users.view)).to.equal(false);
      expect(perm.checkPermission(gPerms.auth.service, gPerms.auth.access)).to.equal(true);
    });
  });
});
