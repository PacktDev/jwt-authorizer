/* eslint no-bitwise: "off" */
import ErrorCustom from '@packt/error-custom';
import Joi from '@hapi/joi';
import jsonVerify from './json-verify';

export default class PermissionManager {
  /**
   * Creates permission object ready to manage
   * @param  {string} globalJSON JSON-encoded list of global services and permissions
   * @param  {string} permsIn Base64-encoded existing permissions (optional)
   */
  constructor(globalJSON, permsIn = undefined) {
    if (!globalJSON) {
      throw new ErrorCustom('No config file supplied', 500, 1000108);
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
    const serviceValidate = Joi.validate(serviceIndex, Joi.number().integer().min(0));
    if (serviceIndex === undefined || serviceValidate.error) {
      throw new ErrorCustom('Invalid serviceIndex', 500, 1000115, serviceValidate.error);
    }

    const permValidate = Joi.validate(perm, Joi.number().integer().min(0));
    if (perm === undefined || permValidate.error) {
      throw new ErrorCustom('Invalid perm number', 500, 1000116, permValidate.error);
    }

    if (serviceIndex >= this.perms.length) {
      throw new ErrorCustom('Service doesn\'t match global permissions object', 500, 1000109);
    }

    this.perms[serviceIndex] |= perm;
  }

  /**
   * @param  {number} serviceIndex Index of the service in the global permissions object
   * @param  {number} perm Value of the permission to remove
   */
  removePermission(serviceIndex, perm) {
    const serviceValidate = Joi.validate(serviceIndex, Joi.number().integer().min(0));
    if (serviceIndex === undefined || serviceValidate.error) {
      throw new ErrorCustom('Invalid serviceIndex', 500, 1000117, serviceValidate.error);
    }

    const permValidate = Joi.validate(perm, Joi.number().integer().min(0));
    if (perm === undefined || permValidate.error) {
      throw new ErrorCustom('Invalid perm number', 500, 1000118, permValidate.error);
    }

    if (serviceIndex >= this.perms.length) {
      throw new ErrorCustom('Service doesn\'t match global permissions object', 500, 1000110);
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
   * @param {string} type
   * Sets type of what is returned
   *
   * @returns {object} Array of strings in the form [service].[permission]
   */
  listPermissions(type) {
    const ownedPerms = [];
    Object.keys(this.gPerms)
      .map((serviceNm) => {
        const service = this.gPerms[serviceNm];
        const servicePermissions = Object.keys(this.gPerms[serviceNm]);

        for (let i = 0; i < servicePermissions.length; i += 1) {
          const servicePermission = servicePermissions[i];
          const value = service[servicePermissions[i]];
          const serviceIdx = this.gPerms[serviceNm].service;
          if (servicePermission !== 'service') {
            if ((this.perms[service.service] & value) === value) {
              switch (type) {
                case 'indices':
                  ownedPerms.push(`[${serviceIdx}].[${value}]`);
                  break;
                case 'complete':
                  ownedPerms.push({
                    serviceName: serviceNm,
                    serviceIndex: serviceIdx,
                    permissionName: servicePermission,
                    permissionIndex: value,
                  });
                  break;
                default:
                  ownedPerms.push(`[${serviceNm}].[${servicePermission}]`);
              }
            }
          }
        }

        return service;
      });

    return ownedPerms;
  }

  /**
  * Encodes multiple permissions
  *
  * @param {Array} permArray
  *
  * @returns {String}
  * Encoded permissions string
  */
  encodeMultiplePermissions(permArray) {
    if (permArray.length === 0) {
      return this.toString();
    }

    if (Array.isArray(permArray)) {
      permArray.forEach((item) => {
        const checkPerms = new Uint8Array(Buffer.from(item, 'base64'));
        checkPerms.forEach((elem, index) => {
          this.perms[index] |= elem;
        });
      });
    }

    return this.toString();
  }

  /**
   * Checks the permission is included in the current permissions object
   * @param  {number} serviceIndex
   * @param  {number} permission
   *
   * @returns {boolean} Whether the permission is included
   */
  checkPermission(serviceIndex, permission) {
    const serviceValidate = Joi.validate(serviceIndex, Joi.number().integer().min(0));
    if (serviceIndex === undefined || serviceValidate.error) {
      throw new ErrorCustom('Invalid serviceIndex', 500, 1000119, serviceValidate.error);
    }

    const permValidate = Joi.validate(permission, Joi.number().integer().min(0));
    if (permission === undefined || permValidate.error) {
      throw new ErrorCustom('Invalid perm number', 500, 1000120, permValidate.error);
    }

    if (serviceIndex >= this.perms.length) {
      throw new ErrorCustom('Service doesn\'t match global permissions object', 500, 1000111);
    }

    return (this.perms[serviceIndex] & permission) === permission;
  }

  /**
   * Checks the permission is included in the supplied encoded permissions object
   *
   * @param  {string} encodedPermissions Base64 encoded permission array
   * @param  {number} serviceIndex Index of the service in the global permissions object
   * @param  {number} permission Value of the permission to check
   *
   * @returns {boolean} Whether the permission is included
   */
  static checkPermissions(encodedPermissions, serviceIndex, permission) {
    const serviceValidate = Joi.validate(serviceIndex, Joi.number().integer().min(0));
    if (serviceIndex === undefined || serviceValidate.error) {
      throw new ErrorCustom('Invalid serviceIndex', 500, 1000121, serviceValidate.error);
    }

    const permValidate = Joi.validate(permission, Joi.number().integer().min(0));
    if (permission === undefined || permValidate.error) {
      throw new ErrorCustom('Invalid perm number', 500, 1000122, permValidate.error);
    }

    const jwtPermissions = new Uint8Array(Buffer.from(encodedPermissions, 'base64'));
    if (serviceIndex >= jwtPermissions.length) {
      return false;
    }

    return (jwtPermissions[serviceIndex] & permission) === permission;
  }
}
