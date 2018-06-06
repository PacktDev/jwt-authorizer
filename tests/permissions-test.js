/* eslint-env node, mocha */
/* eslint-disable no-new */
/* eslint-disable no-unused-expressions */

const JwtAuthorizer = require('../index');
const chai = require('chai'); // eslint-disable-line
const expect = chai.expect; // eslint-disable-line

const gPermsJson = `{
  "genin": {
    "service": 0,
    "dRankMission": 1,
    "cRankMission": 2
  },
  "chunin": {
    "service": 1,
    "bRankMission": 1,
    "aRankMission": 2
  },
  "jonin": {
    "service": 2,
    "sRankMission": 1,
    "potentialKage": 2
  }
}`;

const gPerms = JSON.parse(gPermsJson);

const setup = () => {
  const perm = new JwtAuthorizer.PermissionManager(gPermsJson);
  perm.addPermission(gPerms.genin.service, gPerms.genin.dRankMission);
  perm.addPermission(gPerms.genin.service, gPerms.genin.cRankMission);
  perm.addPermission(gPerms.chunin.service, gPerms.chunin.bRankMission);
  perm.addPermission(gPerms.chunin.service, gPerms.chunin.aRankMission);
  perm.addPermission(gPerms.jonin.service, gPerms.jonin.sRankMission);

  return perm;
};

describe('Permission Manager', () => {
  describe('Constructor', () => {
    it('Fail for service has no numeric service index', () => {
      const gPermsJsonBadService = `{
        "genin": {
          "service": "abc",
          "dRankMission": 1,
          "cRankMission": 2
        },
        "chunin": {
          "service": 1,
          "bRankMission": 1,
          "aRankMission": 2
        }
      }`;

      const badConstructor = () => {
        new JwtAuthorizer.PermissionManager(gPermsJsonBadService);
      };

      expect(badConstructor).to.throw('Service [genin] has no numeric service index');
    });

    it('Fail for service has an index greater than the number of services', () => {
      const gPermsJsonBadService = `{
        "genin": {
          "service": 10,
          "dRankMission": 1,
          "cRankMission": 2
        },
        "chunin": {
          "service": 1,
          "bRankMission": 1,
          "aRankMission": 2
        }
      }`;

      const badConstructor = () => {
        new JwtAuthorizer.PermissionManager(gPermsJsonBadService);
      };

      expect(badConstructor).to.throw('Service [genin] has an index greater than the number of services');
    });

    it('Fail for service index exists twice', () => {
      const gPermsJsonBadService = `{
        "genin": {
          "service": 1,
          "dRankMission": 1,
          "cRankMission": 2
        },
        "chunin": {
          "service": 1,
          "bRankMission": 1,
          "aRankMission": 2
        }
      }`;

      const badConstructor = () => {
        new JwtAuthorizer.PermissionManager(gPermsJsonBadService);
      };

      expect(badConstructor).to.throw('Service index [1] exists twice (extra time in [chunin])');
    });

    it('Fail for service value is not base2', () => {
      const gPermsJsonBadService = `{
        "genin": {
          "service": 0,
          "dRankMission": 3,
          "cRankMission": 2
        },
        "chunin": {
          "service": 1,
          "bRankMission": 1,
          "aRankMission": 2
        }
      }`;

      const badConstructor = () => {
        new JwtAuthorizer.PermissionManager(gPermsJsonBadService);
      };

      expect(badConstructor).to.throw('Value [3] of Key [dRankMission] in Service [0] is not Base2');
    });

    it('Fail for service value exists twice', () => {
      const gPermsJsonBadService = `{
        "genin": {
          "service": 0,
          "dRankMission": 1,
          "cRankMission": 1
        },
        "chunin": {
          "service": 1,
          "bRankMission": 1,
          "aRankMission": 2
        }
      }`;

      const badConstructor = () => {
        new JwtAuthorizer.PermissionManager(gPermsJsonBadService);
      };

      expect(badConstructor).to.throw('Value [1] of Key [cRankMission] in Service [0] exists twice');
    });

    it('Fail for no config file supplied', () => {
      const noConfigFile = () => {
        new JwtAuthorizer.PermissionManager();
      };

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

    it('Has 5 permissions', () => {
      expect(perm.listPermissions()).to.have.lengthOf(5);
    });

    it('Has genin.dRankMission', () => {
      expect(perm.checkPermission(gPerms.genin.service, gPerms.genin.dRankMission)).to.equal(true);
    });

    it('Fail for addPermission', () => {
      try {
        perm.addPermission(4, 3);
      } catch (error) {
        expect(error.message).to.equal('Service doesn\'t match global permissions object');
        expect(error.errorCode).to.equal(1000109);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for removePermission', () => {
      try {
        perm.removePermission(4, 3);
      } catch (error) {
        expect(error.message).to.equal('Service doesn\'t match global permissions object');
        expect(error.errorCode).to.equal(1000110);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for checkPermission', () => {
      try {
        perm.checkPermission(4, 3);
      } catch (error) {
        expect(error.message).to.equal('Service doesn\'t match global permissions object');
        expect(error.errorCode).to.equal(1000111);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for static checkPermission', () => {
      try {
        JwtAuthorizer.PermissionManager.checkPermissions(perm.toString(), 6, 3);
      } catch (error) {
        expect(error.message).to.equal('Service doesn\'t match global permissions object');
        expect(error.errorCode).to.equal(1000112);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Modifying the existing perms by adding jonin.potentialKage', () => {
      const test = new JwtAuthorizer.PermissionManager(gPermsJson, perm.toString());
      test.addPermission(gPerms.jonin.service, gPerms.jonin.potentialKage);

      expect(test.listPermissions()).to.have.lengthOf(6);
      expect(test.checkPermission(gPerms.jonin.service, gPerms.jonin.sRankMission)).to.equal(true);
      expect(test.checkPermission(gPerms.jonin.service, gPerms.jonin.potentialKage)).to.equal(true);
      expect(test.checkPermission(gPerms.genin.service, gPerms.genin.dRankMission)).to.equal(true);
    });

    it('Modifying the existing perms by removing jonin.sRankMission', () => {
      const test = new JwtAuthorizer.PermissionManager(gPermsJson, perm.toString());
      test.removePermission(gPerms.jonin.service, gPerms.jonin.sRankMission);

      expect(test.listPermissions()).to.have.lengthOf(4);
      expect(test.checkPermission(gPerms.jonin.service, gPerms.jonin.sRankMission)).to.equal(false);
      expect(perm.checkPermission(gPerms.genin.service, gPerms.genin.dRankMission)).to.equal(true);
    });
  });
});
