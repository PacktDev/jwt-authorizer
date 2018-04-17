module.exports = (gPerms) => {
  const services = [];
  Object.keys(gPerms)
    .map(key => ({ key, service: gPerms[key] }))
    .forEach((item) => {
      const keys = Object.keys(item.service);
      const serviceNum = item.service.service;

      if (serviceNum === undefined) {
        throw new Error(`Service [${item.key}] has no service index`);
      }

      if (serviceNum >= Object.keys(gPerms).length) {
        throw new Error(`Service [${item.key}] has an index greater than the number of services`);
      }

      if (services.find(service => service === serviceNum)) {
        throw new Error(`Service index [${serviceNum}] exists twice (extra time in [${item.key}])`);
      } else {
        services.push(serviceNum);
      }

      const numbers = [];
      for (let i = 0; i < keys.length; i += 1) {
        const key = keys[i];
        const value = item.service[keys[i]];
        if (key !== 'service') {
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
    });
};
