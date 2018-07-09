/* eslint-env node, mocha */
/* eslint-disable no-new */
/* eslint-disable no-unused-expressions */

const JwtAuthorizer = require('../src/index');
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

    it('Fail for addPermission service out of range', () => {
      try {
        perm.addPermission(4, 3);
        expect(0).to.equal('fail happy path');
      } catch (error) {
        expect(error.message).to.equal('Service doesn\'t match global permissions object');
        expect(error.errorCode).to.equal(1000109);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for addPermission service not a number', () => {
      try {
        perm.addPermission('service', 3);
        expect(0).to.equal('fail happy path');
      } catch (error) {
        expect(error.message).to.equal('Invalid serviceIndex');
        expect(error.errorCode).to.equal(1000115);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for addPermission perm not a number', () => {
      try {
        perm.addPermission(3, 'perm');
        expect(0).to.equal('fail happy path');
      } catch (error) {
        expect(error.message).to.equal('Invalid perm number');
        expect(error.errorCode).to.equal(1000116);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for removePermission service out of range', () => {
      try {
        perm.removePermission(4, 3);
        expect(0).to.equal('fail happy path');
      } catch (error) {
        expect(error.message).to.equal('Service doesn\'t match global permissions object');
        expect(error.errorCode).to.equal(1000110);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for removePermission service not a number', () => {
      try {
        perm.removePermission('service', 3);
        expect(0).to.equal('fail happy path');
      } catch (error) {
        expect(error.message).to.equal('Invalid serviceIndex');
        expect(error.errorCode).to.equal(1000117);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for removePermission perm not a number', () => {
      try {
        perm.removePermission(3, 'perm');
        expect(0).to.equal('fail happy path');
      } catch (error) {
        expect(error.message).to.equal('Invalid perm number');
        expect(error.errorCode).to.equal(1000118);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for checkPermission service out of range', () => {
      try {
        perm.checkPermission(4, 3);
        expect(0).to.equal('fail happy path');
      } catch (error) {
        expect(error.message).to.equal('Service doesn\'t match global permissions object');
        expect(error.errorCode).to.equal(1000111);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for checkPermission service not a number', () => {
      try {
        perm.checkPermission('service', 3);
        expect(0).to.equal('fail happy path');
      } catch (error) {
        expect(error.message).to.equal('Invalid serviceIndex');
        expect(error.errorCode).to.equal(1000119);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for checkPermission perm not a number', () => {
      try {
        perm.checkPermission(3, 'perm');
        expect(0).to.equal('fail happy path');
      } catch (error) {
        expect(error.message).to.equal('Invalid perm number');
        expect(error.errorCode).to.equal(1000120);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('False for static checkPermission out of range', () => {
      expect(JwtAuthorizer.PermissionManager.checkPermissions(perm.toString(), 6, 3))
        .to.equal(false);
    });

    it('Fail for static checkPermission service not a number', () => {
      try {
        JwtAuthorizer.PermissionManager.checkPermissions(perm.toString(), 'service', 3);
        expect(0).to.equal('fail happy path');
      } catch (error) {
        expect(error.message).to.equal('Invalid serviceIndex');
        expect(error.errorCode).to.equal(1000121);
        expect(error.statusCode).to.equal(500);
      }
    });

    it('Fail for static checkPermission perm not a number', () => {
      try {
        JwtAuthorizer.PermissionManager.checkPermissions(perm.toString(), 3, 'perm');
        expect(0).to.equal('fail happy path');
      } catch (error) {
        expect(error.message).to.equal('Invalid perm number');
        expect(error.errorCode).to.equal(1000122);
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

    it('listPermissions returns names when type is set to names', () => {
      const test = new JwtAuthorizer.PermissionManager(gPermsJson, perm.toString());
      const listedPerms = test.listPermissions();
      expect(listedPerms).to.have.lengthOf(5);
      expect(listedPerms[0]).to.equal('[genin].[dRankMission]');
      expect(listedPerms[1]).to.equal('[genin].[cRankMission]');
      expect(listedPerms[2]).to.equal('[chunin].[bRankMission]');
      expect(listedPerms[3]).to.equal('[chunin].[aRankMission]');
      expect(listedPerms[4]).to.equal('[jonin].[sRankMission]');

    });

    it('listPermissions returns indicies when type is set to indices', () => {
      const test = new JwtAuthorizer.PermissionManager(gPermsJson, perm.toString());
      const listedPerms = test.listPermissions('indices');

      expect(listedPerms).to.have.lengthOf(5);
      expect(listedPerms[0]).to.equal('[0].[1]');
      expect(listedPerms[1]).to.equal('[0].[2]');
      expect(listedPerms[2]).to.equal('[1].[1]');
      expect(listedPerms[3]).to.equal('[1].[2]');
      expect(listedPerms[4]).to.equal('[2].[1]');
    });

    it('listPermissions returns complete pemissions object when type is set to complete', () => {
      const test = new JwtAuthorizer.PermissionManager(gPermsJson, perm.toString());
      const listedPerms = test.listPermissions('complete');

      expect(listedPerms).to.have.lengthOf(5);
      expect(listedPerms[0]).to.be.instanceOf(Object);
      expect(listedPerms[0].permissionName).to.equal('dRankMission');
      expect(listedPerms[1].serviceIndex).to.equal(0);
      expect(listedPerms[1].permissionIndex).to.equal(2);
      expect(listedPerms[2].serviceName).to.equal('chunin');
      expect(listedPerms[2].serviceIndex).to.equal(1);
      expect(listedPerms[4].serviceName).to.equal('jonin');
      expect(listedPerms[4].serviceIndex).to.equal(2);


    });
  });
});
