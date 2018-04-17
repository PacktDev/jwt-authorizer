module.exports = (gPerms) => {
  const services = [];
  Object.keys(gPerms)
    .map((key) => {
      const service = gPerms[key];
      const keys = Object.keys(service);
      const serviceNum = parseInt(service.service, 10);
      if (Number.isNaN(serviceNum)) {
        throw new Error(`Service [${key}] has no numeric service index`);
      }

      if (serviceNum >= Object.keys(gPerms).length) {
        throw new Error(`Service [${key}] has an index greater than the number of services`);
      }

      if (services.find(eachService => eachService === serviceNum)) {
        throw new Error(`Service index [${serviceNum}] exists twice (extra time in [${key}])`);
      } else {
        services.push(serviceNum);
      }

      const numbers = [];
      for (let i = 0; i < keys.length; i += 1) {
        const permissionKey = keys[i];
        const value = service[keys[i]];
        if (permissionKey !== 'service') {
          if (Math.log2(value) !== parseInt(Math.log2(value), 10)) {
            throw new Error(`Value [${value}] is not Base2`);
          }

          if (numbers.find(number => number === value)) {
            throw new Error(`Value [${value}] exists twice`);
          } else {
            numbers.push(value);
          }
        }
      }

      return key;
    });
};
