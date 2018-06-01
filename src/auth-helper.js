import jwt from 'jsonwebtoken';

import PermissionManager from './permission-manager';

export default class AuthHelper {
  /**
   * Instantiates the helper object with raw information needed.
   * @param {string} rawJwt Raw Authorization header, including Bearer.
   * @param {string} publicKey Public key to verify signature of the JWT.
   * @param {object} globalPerms Object representing the permission structure.
   * @param {object} service Service from global permissions object.
   * @param {object} overrideAccessPermission Permission from global permissions in
   * service that allows a user to retrieve another user's details.
   */
  constructor(rawJwt, publicKey, service, overrideAccessPermission) {
    this.rawJwt = rawJwt;
    this.publicKey = publicKey;
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
      if (!(/^Bearer [a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+?$/.test(this.rawJwt))) return reject(new Error('Malformed JWT passed in'));
      const splitJwt = this.rawJwt.replace('Bearer ', '');
      return jwt.verify(splitJwt, this.publicKey, (err, decoded) => {
        if (err) return reject(err);
        if (decoded.permissions) this.permissions = decoded.permissions;
        if (decoded.userId) {
          if (userId === 'me' || userId === decoded.userId || !userId) return resolve(decoded.userId);
          return this.userCan(this.service, this.overrideAccessPermission)
            .then((result) => {
              if (result) return resolve(userId);
              return reject(new Error('Mismatching userId'));
            });
        }

        return reject(new Error('Unable to decode for userId'));
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
