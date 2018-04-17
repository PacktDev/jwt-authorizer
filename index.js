/* eslint no-bitwise: "off" */

const jwt = require('jsonwebtoken');
const jsonVerify = require('./src/json-verify');

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
    jsonVerify(this.gPerms);

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
   * @param  {number} serviceIndex Index of the service in the global permissions object
   * @param  {number} perm Value of the permission to add
   */
  addPermission(serviceIndex, perm) {
    if (serviceIndex >= this.perms.length) {
      throw new Error('Service doesn\'t match global permissions object');
    }
    this.perms[serviceIndex] |= perm;
  }

  /**
   * @param  {number} serviceIndex Index of the service in the global permissions object
   * @param  {number} perm Value of the permission to remove
   */
  removePermission(serviceIndex, perm) {
    if (serviceIndex >= this.perms.length) {
      throw new Error('Service doesn\'t match global permissions object');
    }
    this.perms[serviceIndex] &= ~perm;
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

class JwtAuthorizer {
  constructor(accessToken, publicKey) {
    this.accessToken = accessToken;
    this.publicKey = publicKey;
  }

  verifyDecode() {
    if (jwt.verify(this.accessToken, this.publicKey)) {
      return jwt.decode(this.accessToken);
    }

    throw Error('Invalid token');
  }
}

module.exports = {
  PermissionManager,
  JwtAuthorizer,
};
