/*
 * Copyright (c) 2024, Polarity.io, Inc.
 */
const fs = require('fs');
const request = require('postman-request');
const config = require('../config/config');

class RequestWithDefaults {
  constructor() {
    const { request: reqConfig } = config;
    const defaults = {};

    if (reqConfig.cert && fs.existsSync(reqConfig.cert)) defaults.cert = fs.readFileSync(reqConfig.cert);
    if (reqConfig.key && fs.existsSync(reqConfig.key)) defaults.key = fs.readFileSync(reqConfig.key);
    if (reqConfig.passphrase) defaults.passphrase = reqConfig.passphrase;
    if (reqConfig.ca && fs.existsSync(reqConfig.ca)) defaults.ca = fs.readFileSync(reqConfig.ca);
    if (reqConfig.proxy) defaults.proxy = reqConfig.proxy;
    if (typeof reqConfig.rejectUnauthorized === 'boolean') {
      defaults.rejectUnauthorized = reqConfig.rejectUnauthorized;
    }

    this._defaultsRequest = request.defaults(defaults);
  }

  async request(requestOptions) {
    return new Promise((resolve, reject) => {
      this._defaultsRequest(requestOptions, (err, response) => {
        if (err) return reject(err);
        resolve(response);
      });
    });
  }
}

module.exports = new RequestWithDefaults();
