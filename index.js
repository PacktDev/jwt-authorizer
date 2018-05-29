/* eslint no-bitwise: "off" */

import jwt from 'jsonwebtoken';

class PermissionManager {
  /**
   * Creates permission object ready to manage
   * @param  {string} globalJSON JSON-encoded list of global services and permissions
   * @param  {string} permsIn Base64-encoded existing permissions (optional)
   */
  constructor(globalJSON, permsIn = undefined) {
    if (!globalJSON) {
      throw Error('No config file supplied');
    }

    this.gPerms = JSON.parse(globalJSON);
    // always initialise to length of full permissions array
    this.perms = new Uint8Array(Object.keys(this.gPerms).length);

    // check for existing perms passed in and map to array
    if (permsIn) {
      const checkPerms = new Uint8Array(Buffer.from(permsIn, 'base64'));
      checkPerms.forEach((item, index) => {
        this.perms[index] = item;
      });
    }
  }

  /**
   * Adds a permimssion into the internal permission object
   *
   * @param  {number} service Index of the service in the global permissions object
   * @param  {number} perm Value of the permission to add
   */
  addPermission(service, perm) {
    if (service >= this.perms.length) {
      throw new Error('Service doesn\'t match global permissions object');
    }
    this.perms[service] |= perm;
  }

  /**
   * @param  {number} service Index of the service in the global permissions object
   * @param  {number} perm Value of the permission to remove
   */
  removePermission(service, perm) {
    if (service >= this.perms.length) {
      throw new Error('Service doesn\'t match global permissions object');
    }
    this.perms[service] &= ~perm;
  }
  /**
   * Returns a base64 version of the permissions array to be stored in a JWT
   *
   * @returns {string} Base64 encoded version of the array
   */
  toString() {
    return Buffer.from(this.perms).toString('base64');
  }

  /**
   * Returns an array of permissions set for the current object
   *
   * @returns {object} Array of strings in the form [service].[permission]
   */
  listPermissions() {
    const ownedPerms = [];
    Object.keys(this.gPerms)
      .map(key => ({ key, service: this.gPerms[key] }))
      .forEach((item) => {
        const serviceName = item.key;
        const servicePermissions = Object.keys(item.service);

        for (let i = 0; i < servicePermissions.length; i += 1) {
          const servicePermission = servicePermissions[i];
          const value = item.service[servicePermissions[i]];
          if (servicePermission !== 'service') {
            if ((this.perms[item.service.service] & value) === value) {
              ownedPerms.push(`[${serviceName}].[${servicePermission}]`);
            }
          }
        }
      });
    return ownedPerms;
  }
  /**
   * Checks the permission is included in the supplied encoded permissions object
   *
   * @param  {string} encodedPermissions Base64 encoded permission array
   * @param  {number} service Index of the service in the global permissions object
   * @param  {number} permission Value of the permission to check
   */
  static checkPermissions(encodedPermissions, service, permission) {
    const jwtPermissions = new Uint8Array(Buffer.from(encodedPermissions, 'base64'));

    return (jwtPermissions[service] & permission) === permission;
  }
}

class AuthHelper {
  /**
   * Instantiates the helper object with raw information needed.
   * @param {string} rawJwt Raw Authorization header, incliuding Bearer.
   * @param {string} publicKey Public key to verify signature of the JWT.
   * @param {object} globalPerms Object representing the permission structure.
   */
  constructor(rawJwt, publicKey, service, masqueradePermission) {
    this.rawJwt = rawJwt;
    this.publicKey = publicKey;
    this.service = service;
    this.masqueradePermission = masqueradePermission;
  }

  /**
   * Validates the JWT for structure and signature.
   *
   * @returns {Promise<string>} Promise which resolves to the userId.
   */
  processJwt(userId) {
    return new Promise((resolve, reject) => {
      jwt.verify(this.rawJwt, this.publicKey, (err, decoded) => {
        if (err) return reject(err);
        if (decoded.permissions) this.permissions = decoded.permissions;
        if (decoded.userId) {
          if (userId === 'me' || !userId) return resolve(decoded.userId);
          if (userId !== decoded.userId) {
            return this.userCan(this.service, this.masqueradePermission)
              .then((result) => {
                if (result) return resolve(decoded.userId);
                return reject(new Error('Mismatching userId'));
              });
          }
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
    return Promise.Resolve(PermissionManager
      .checkPermissions(this.permissions, permissionClass, permission));
  }
}

module.exports = {
  PermissionManager,
  AuthHelper,
};
