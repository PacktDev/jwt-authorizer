# jwt-authorizer

Use this package for checking a users authentication and authorization in a microservice environment, and to encode their permissions into the JWT. There are 2 classes within this package, `AuthHelper` and `PermissionManager`.

Exceptions are thrown using the `@packt/error-custom` error type, with unique error codes:

```
Code    Class             Function                Description
------- ----------------- ----------------------- -----------------------------------
1000100 AuthHelper        processJwt              JWT verification failed
1000101 AuthHelper        processJwt              UserId doesn't match and no permission to override
1000102 AuthHelper        processJwt              No userId in token
1000103 VerifyJson        VerifyJson              Service [${key}] has no numeric service index
1000104 VerifyJson        VerifyJson              Service [${key}] has an index greater than the number of services
1000105 VerifyJson        VerifyJson              Service index [${serviceNum}] exists twice (extra time in [${key}])
1000106 VerifyJson        VerifyJson              Value [${value}] of Key [${permissionKey}] in Service [${serviceNum}] is not Base2
1000107 VerifyJson        VerifyJson              Value [${value}] of Key [${permissionKey}] in Service [${serviceNum}] exists twice
1000108 PermissionManager constructor             No config file supplied
1000109 PermissionManager addPermission           Service doesn't match global permissions object
1000110 PermissionManager removePermission        Service doesn't match global permissions object
1000111 PermissionManager checkPermission         Service doesn't match global permissions object
1000112 PermissionManager static checkPermission  Service doesn't match global permissions object
1000113 AuthHelper        processJwt              Invalid Jwt format
1000114 AuthHelper        constructor             Invalid public key format
```

## Requirements

* Nodejs >= 8.10

## Permission Structures

The JWT itself defines whether a user is authenticated, and a specific object structure is used to manage permissions. This has been designed to encode full permissions into the JWT in a minimal amount of space, and allow the consuming microservice to check permissions without a call to a central service, reducing processing time and direct runtime dependency.

Permissions are detailed as an object with the following format:
```
{
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
}
```
Top level objects are individual services, and each must contain a `service` property with a numeric index. These must be 0 based, unique and no higher than the number of objects-1.

Within each object are permission properties, which are base2 numbers.

This object structure is passed into the `PermissionManager` class as a JSON string and validated for correct structure. It is recommended that the JSON is stored in the authentication and authorization service (that generates the JWTs) and validated as part of the build step.

The permissions a user has can he held in a `UInt8Array` which base64 encodes to an extremely short string to be put into the JWT.

### Limitations

As the `UInt8Array` can only store 8 bits per service, there can only be 8 permissions per service. Any services needing more permissions will need to be split over 2 'virtual' services.

## AuthHelper

`AuthHelper` is to be used in microservices to verify if the user has a valid authentication and authorization.

### Methods

`constructor(rawJwt, publicKey, service, overrideAccessPermission)`

Instantiates the helper object with raw information needed.
   * @param {string} rawJwt Raw Authorization header, including Bearer.
   * @param {string} publicKey Public key to verify signature of the JWT. Raw string or base64 encoded.
   * @param {object} service Service from global permissions object [optional].
   * @param {object} overrideAccessPermission Permission from global permissions in
      service that allows a user to retrieve another user's details [optional].

`processJwt(userId)`

Validates the JWT for structure and signature.
   * @param {string} userId UserId to test against the JWT. Allows me to delegate `userId` to JWT, when a different `userId` is provided then a permission check is made using the `service` and `overrideAccesspermission` specified in the constructor.
   * @param {boolean} returnPayload. default to false. Sets payload after error when set to true if error was `jwt expired`
   * @returns {Promise<string>} Promise which resolves to the userId.

`userCan(permissionClass, permission)`

Checks whether the user has the required permission.
   * @param {string} permissionClass The class or service.
   * @param {string} permission The permission.
   * @returns {Promise<boolean>} Promise which resolves to true or false.

## PermissionManager

`PermissionManager` is to be used in microservices to verify if the user has a valid authentication and authorization.

### Methods

`constructor(globalJSON, permsIn = undefined)`

Creates permission object ready to manage.
   * @param  {string} globalJSON JSON-encoded list of global services and permissions.
   * @param  {string} permsIn Base64-encoded existing permissions (optional).

`addPermission(serviceIndex, perm)`

Adds a permimssion into the internal permission object.
   * @param  {number} serviceIndex Index of the service in the global permissions object.
   * @param  {number} perm Value of the permission to add.

`removePermission(serviceIndex, perm)`

Removes a permimssion from the internal permission object.
   * @param  {number} serviceIndex Index of the service in the global permissions object.
   * @param  {number} perm Value of the permission to remove.

`toString()`

Returns a base64 version of the permissions array to be stored in a JWT.
   * @returns {string} Base64 encoded version of the array.

`listPermissions()`

Returns an array of permissions set for the current object.
   * @returns {object} Array of strings in the form [service].[permission].

`checkPermission(serviceIndex, permission)`

Checks the permission is included in the current permissions object.
   * @param  {number} serviceIndex.
   * @param  {number} permission.
   * @returns {boolean} Whether the permission is included.

`static checkPermissions(encodedPermissions, serviceIndex, permission)`

Checks the permission is included in the supplied encoded permissions object.
   * @param  {string} encodedPermissions Base64 encoded permission array.
   * @param  {number} serviceIndex Index of the service in the global permissions object.
   * @param  {number} permission Value of the permission to check.
   * @returns {boolean} Whether the permission is included.
