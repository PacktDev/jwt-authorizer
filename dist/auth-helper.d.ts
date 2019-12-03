declare class AuthHelper {
  /**
   * Instantiates the helper object with raw information needed.
   * @param {string} rawJwt Raw Authorization header, including Bearer.
   * @param {string} publicKey Public key to verify signature of the JWT, raw string
   * or base64 encoded.
   * @param {object} service Service from global permissions object.
   * @param {object} overrideAccessPermission Permission from global permissions in
   * service that allows a user to retrieve another user's details.
   */
  constructor(rawJwt: string, publicKey: string, service: number, overrideAccessPermission: number);

  /**
   * Validates the JWT for structure and signature.
   * @param {string} userId UserId to test against the JWT.
   * @param {string} returnPayload Override to allow processing of an expired token.
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
   * @return {string} UserId from the valid JWT
   */
  getDecodedUserId(): string;
}
