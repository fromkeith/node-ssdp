This is a fork of diversario/node-ssdp to try enable SSDP on Chrome Apps.

## Limitations

* Chrome does not currently support socket reuse. As such, this will try close the socket you want before trying to open it.
* As chrome sockets creation/modification is asynchronous, this API is not a direct match to diversario/node-ssdp
* Still testing this; so there are bugs
    * Documentation below is not currently 100% accurate
    * broke cover testing as browserify doesn't like those methods of requires.




## Usage - Client (Untested)

```javascript
    var Client = require('node-ssdp').Client
      , client = new Client();

    client.on('response', function (headers, statusCode, rinfo) {
      console.log('Got a response to an m-search.');
    });

    // search for a service type
    client.search('urn:schemas-upnp-org:service:ContentDirectory:1');

    // Or get a list of all services on the network

    client.search('ssdp:all');
```

## Usage - Server (Currently Testing)

```javascript
    var Server = require('node-ssdp').Server;

    // wait for the callback before adding an USNs.
    var server = new SSDP({log: true}, undefined, function (err, server) {
      server.addUSN('upnp:rootdevice');
      server.addUSN('urn:schemas-upnp-org:device:MediaServer:1');
      server.addUSN('urn:schemas-upnp-org:service:ContentDirectory:1');
      server.addUSN('urn:schemas-upnp-org:service:ConnectionManager:1');

      server.on('advertise-alive', function (headers) {
        // Expire old devices from your cache.
        // Register advertising device somewhere (as designated in http headers heads)
      });

      server.on('advertise-bye', function (headers) {
        // Remove specified device from cache.
      });

      // start the server. Wait for the callback before advertising or sending.
      server.start(function (err) {
        console.log(err);
      });
    });

```


##Configuration (not all options tested)
`new SSDP([options, [socket], callback])`

SSDP constructor accepts an optional configuration object and an optional initialized socket. At the moment, the following is supported:

- `logLevel` _String_ Specifies log level to print. Possible values: `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`. If not explicitly set in options logging is disabled completely.
- `logJSON` _Boolean_ Log JSON strings (using [bunyan](https://github.com/trentm/node-bunyan)). Default: `true`.
- `ssdpSig` _String_ SSDP signature. Default: `node.js/NODE_VERSION UPnP/1.1 node-ssdp/PACKAGE_VERSION`
- `ssdpIp` _String_ SSDP multicast group. Default: `239.255.255.250`.
- `ssdpPort` _Number_ SSDP port. Default: `1900`
- `ssdpTtl` _Number_ Multicast TTL. Default: `1`
- `adInterval` _Number_ `advertise` event frequency (ms). Default: 10 sec.
- `unicastHost` _String_ IP address or hostname of server where SSDP service is running. This is used in `HOST` header. Default: `0.0.0.0`.
- `location` _String_ URL pointing to description of your service, or a function which returns that URL
- `udn` _String_ Unique Device Name. Default: `uuid:f40c2981-7329-40b7-8b04-27f187aecfb5`.
- `description` _String_ Path to description file. Default: `upnp/desc.php`.
- `ttl` _Number_ Packet TTL. Default: `1800`.
- `allowWildcards` _Boolean_ Accept wildcards (`*`) in `serviceTypes` of `M-SEARCH` packets, e.g. `usn:Belkin:device:**`. Default: `false`

###Logging (not tested)
Aside from `logLevel` configuration option you can set the level via an environment variable `LOG_LEVEL`, which overrides configuration.

At log levels `DEBUG` and `TRACE` module will print call source location.

Use `bunyan` CLI tool to pretty-print JSON logs; running the module with pretty-print enabled is not recommended. 

# License

(The MIT License)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

