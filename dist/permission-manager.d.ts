declare class PermissionManager {
  /**
   * Creates permission object ready to manage
   * @param  {string} globalJSON JSON-encoded list of global services and permissions
   * @param  {string} permsIn Base64-encoded existing permissions (optional)
   */
  constructor(globalJSON: string, permsIn = undefined);

  /**
   * Adds a permimssion into the internal permission object
   *
   * @param  {number} serviceIndex Index of the service in the global permissions object
   * @param  {number} perm Value of the permission to add
   */
  addPermission(serviceIndex: number, perm: number): void;

  /**
   * @param  {number} serviceIndex Index of the service in the global permissions object
   * @param  {number} perm Value of the permission to remove
   */
  removePermission(serviceIndex: number, perm: number): void;

  /**
   * Returns a base64 version of the permissions array to be stored in a JWT
   *
   * @returns {string} Base64 encoded version of the array
   */
  toString(): string;

  /**
   * Returns an array of permissions set for the current object
   *
   * @param {string} type
   * Sets type of what is returned. Possible values are 'indices' or 'complete'
   *
   * @returns {string[]} Array of strings in the form [service].[permission]
   */
  listPermissions(type: string): string[];

  /**
   * Encodes multiple permissions
   *
   * @param {string[]} permArray
   *
   * @returns {String}
   * Encoded permissions string
   */
  encodeMultiplePermissions(permArray: string[]): string;

  /**
   * Checks the permission is included in the current permissions object
   * @param  {number} serviceIndex
   * @param  {number} permission
   *
   * @returns {boolean} Whether the permission is included
   */
  checkPermission(serviceIndex: number, permission: number): boolean;

  /**
   * Checks the permission is included in the supplied encoded permissions object
   *
   * @param  {string} encodedPermissions Base64 encoded permission array
   * @param  {number} serviceIndex Index of the service in the global permissions object
   * @param  {number} permission Value of the permission to check
   *
   * @returns {boolean} Whether the permission is included
   */
  static checkPermissions(encodedPermissions: string, serviceIndex: number, permission: number): boolean;
}