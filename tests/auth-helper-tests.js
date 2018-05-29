/* eslint-env node, mocha */
/* eslint-disable no-unused-expressions */

import sinon from 'sinon'; // eslint-disable-line
import chai, { expect } from 'chai'; // eslint-disable-line
import NodeRSA from 'node-rsa';
import jwt from 'jsonwebtoken';
import chaiaspromised from 'chai-as-promised';

import { AuthHelper } from '../index';

chai.use(chaiaspromised);

const gPermsJSON = '{"auth":{"service":0,"access":1,"createRole":2,"assignPermToRole":4,"assignRoleToUser":8},"credits":{"service":1,"giveOne":1,"giveMany":2},"videoCaptions":{"service":2,"canUpload":1},"users":{"service":3,"view":1,"edit":2}}';
const gPerms = JSON.parse(gPermsJSON);
const key = new NodeRSA({ b: 512 });
const privKey = key.exportKey('pkcs8');
const pubKey = key.exportKey('public');

console.log(privKey);
console.log(pubKey);

const payload = {
  userId: '3c1b128a-8baa-41f8-98a9-67023ea545a2',
  username: 'test@mctestface.com',
};

const validToken = jwt.sign(payload, privKey, { algorithm: 'RS256' });
console.log(validToken);

describe('Auth Helper', () => {
  /* Constructor */
  describe('Valid JWT', () => {
    it('Valid JWT decoded has userId returned', () => {
      const auth = new AuthHelper(validToken, pubKey, gPerms.auth.service, gPerms.auth.canMasquerade);
      expect(auth.processJwt()).to.eventually.equal(payload.userId);
    });

    it('Valid JWT decoded passed with me has userId returned', () => {
      const auth = new AuthHelper(validToken, pubKey, gPerms.auth.service, gPerms.auth.canMasquerade);
      expect(auth.processJwt('me')).to.eventually.equal(payload.userId);
    });

    it('Valid JWT decoded passed with different userId and perm returns userId', () => {
      const auth = new AuthHelper(validToken, pubKey, gPerms.auth.service, gPerms.auth.canMasquerade);
      const fakePerm = sinon.stub(auth, 'userCan').resolves(true);
      expect(auth.processJwt('differentUser')).to.eventually.equal(payload.userId);
      fakePerm.restore();
    });

    it('Valid JWT decoded passed with different userId has userId returned', () => {
      const auth = new AuthHelper(validToken, pubKey, gPerms.auth.service, gPerms.auth.canMasquerade);
      expect(auth.processJwt('differentUser')).to.be.rejectedWith('Mismatching userId');
    });

    it('Valid JWT no userId throws error', () => {
      const auth = new AuthHelper(jwt.sign({}, privKey, { algorithm: 'RS256' }), pubKey, gPerms.auth.service, gPerms.auth.canMasquerade);
      const verifyCall = auth.processJwt();
      expect(verifyCall).to.be.rejectedWith('Unable to decode for userId');
    });

    it('Invalid JWT throws error', () => {
      const auth = new AuthHelper(`${validToken} invalidation string`, pubKey, gPerms.auth.service, gPerms.auth.canMasquerade);
      expect(auth.processJwt()).to.be.rejectedWith('invalid token');
    });
  });
});
