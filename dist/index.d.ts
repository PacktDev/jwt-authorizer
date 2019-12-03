// Type definitions for @packt/jwt-authorizer
// Project: JWT Authorizer
// Definitions by: Chris Key

declare module '@packt/jwt-authorizer' {
  declare class AuthHelper {
    /**
     * Instantiates the helper object with raw information needed.
     * @param {string} rawJwt Raw Authorization header, including Bearer.
     * @param {string} publicKey Public key to verify signature of the JWT, raw string
     * or base64 encoded.
     * @param {number} service Service from global permissions object.
     * @param {number} overrideAccessPermission Permission from global permissions in
     * service that allows a user to retrieve another user's details.
     */
    constructor(rawJwt: string, publicKey: string, service: number, overrideAccessPermission: number);

    /**
     * Validates the JWT for structure and signature.
     * @param {string} userId UserId to test against the JWT.
     * @param {boolean} returnPayload Override to allow processing of an expired token.
     * @returns {Promise<string>} Promise which resolves to the userId.
     * UserId returned is the userId from the token if `me` or falsy is passed in.
     * If not, the userId passed in is returned if it matches the token or the user
     * has the override permission.
     */
    processJwt(userId: string, returnPayload = false): Promise<string>;

    /**
     * Returns the payload from the JWT. Only has value if the processJwt has
     * been called. Does not include the created, expires, permissions or
     * perms properties.
     * @returns {object} Payload from the JWT.
     */
    getPayload(): any;

    /**
     * Checks whether the user has the required permission.
     *
     * @param {number} permissionClass The class or service index.
     * @param {number} permission The permission value.
     * @returns {Promise<boolean>} Promise which resolves to true or false.
     */
    userCan(permissionClass: number, permission: number): Promise<boolean>;

    /**
     * Retrieve the decoded userId from the JWT Token
     * @returns {string} UserId from the valid JWT
     */
    getDecodedUserId(): string;
  }

  declare class PermissionManager {
    /**
     * Creates permission object ready to manage
     * @param  {string} globalJSON JSON-encoded list of global services and permissions
     * @param  {string} permsIn Base64-encoded existing permissions (optional)
     */
    constructor(globalJSON: string, permsIn?: string);

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
}