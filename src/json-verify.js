import ErrorCustom from '@packt/error-custom';

const VerifyJson = (gPerms) => {
  const services = [];
  Object.keys(gPerms)
    .map((key) => {
      const service = gPerms[key];
      const keys = Object.keys(service);
      const serviceNum = parseInt(service.service, 10);
      if (Number.isNaN(serviceNum)) {
        throw new ErrorCustom(`Service [${key}] has no numeric service index`, 500, 1000103);
      }

      if (serviceNum >= Object.keys(gPerms).length) {
        throw new ErrorCustom(`Service [${key}] has an index greater than the number of services`, 500, 1000104);
      }

      if (services.find((eachService) => eachService === serviceNum)) {
        throw new ErrorCustom(`Service index [${serviceNum}] exists twice (extra time in [${key}])`, 500, 1000105);
      } else {
        services.push(serviceNum);
      }

      const numbers = [];
      for (let i = 0; i < keys.length; i += 1) {
        const permissionKey = keys[i];
        const value = service[keys[i]];
        if (permissionKey !== 'service') {
          if (Math.log2(value) !== parseInt(Math.log2(value), 10)) {
            throw new Error(`Value [${value}] of Key [${permissionKey}] in Service [${serviceNum}] is not Base2`, 500, 1000106);
          }

          if (numbers.find((number) => number === value)) {
            throw new Error(`Value [${value}] of Key [${permissionKey}] in Service [${serviceNum}] exists twice`, 500, 1000107);
          } else {
            numbers.push(value);
          }
        }
      }

      return key;
    });
};

export default VerifyJson;
