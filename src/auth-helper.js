import jwt from 'jsonwebtoken';
import ErrorCustom from '@packt/error-custom';

import PermissionManager from './permission-manager';

export default class AuthHelper {
  /**
   * Instantiates the helper object with raw information needed.
   * @param {string} rawJwt Raw Authorization header, including Bearer.
   * @param {string} publicKey Public key to verify signature of the JWT, raw string
   * or base64 encoded.
   * @param {object} service Service from global permissions object.
   * @param {object} overrideAccessPermission Permission from global permissions in
   * service that allows a user to retrieve another user's details.
   */
  constructor(rawJwt, publicKey, service, overrideAccessPermission) {
    this.rawJwt = rawJwt;
    if (publicKey.startsWith('----')) {
      this.publicKey = publicKey;
    } else {
      this.publicKey = Buffer.from(publicKey, 'base64').toString('utf8');
      if (!this.publicKey.startsWith('----')) {
        throw new ErrorCustom('Public key could not be read properly', 500, 1000114);
      }
    }

    this.service = service;
    this.overrideAccessPermission = overrideAccessPermission;
  }

  /**
   * Validates the JWT for structure and signature.
   * @param {string} userId UserId to test against the JWT.
   * @returns {Promise<string>} Promise which resolves to the userId.
   */
  processJwt(userId) {
    return new Promise((resolve, reject) => {
      if (!(/^Bearer [a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+?$/.test(this.rawJwt))) return reject(new ErrorCustom('Malformed JWT passed in', 400, 1000113));
      const splitJwt = this.rawJwt.replace('Bearer ', '');
      return jwt.verify(splitJwt, this.publicKey, (err, decoded) => {
        if (err) return reject(new ErrorCustom(err.message, 401, 1000100));
        if (decoded.permissions) this.permissions = decoded.permissions;
        if (decoded.userId) {
          if (userId === 'me' || userId === decoded.userId || !userId) return resolve(decoded.userId);
          return this.userCan(this.service, this.overrideAccessPermission)
            .then((result) => {
              if (result) return resolve(userId);
              return reject(new ErrorCustom('Mismatching userId', 403, 1000101));
            });
        }

        return reject(new ErrorCustom('Unable to decode for userId', 401, 1000102));
      });
    });
  }

  /**
   * Checks whether the user has the required permission.
   *
   * @param {string} permissionClass The class or service.
   * @param {string} permission The permission.
   * @returns {Promise<boolean>} Promise which resolves to true or false.
   */
  userCan(permissionClass, permission) {
    if (!this.permissions) return Promise.resolve(false);
    return Promise.resolve(PermissionManager
      .checkPermissions(this.permissions, permissionClass, permission));
  }
}
