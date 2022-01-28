const http = require('http')
const https = require('https')
const tls = require('tls')
const fs = require('fs')
const path = require('path')
const config = require('./config.json')

let availableServers = config.servers.map(server => {
  if (server.host.startsWith('*')) {
    server.isWildcard = true
    server.matches = server.host.slice(2)

    return server
  } else return server
})

let secureContexts = {}
let wildcards = []

function createSecureContext(certInfo) {
  let certPath = certInfo.sslCertPath
  let certHost = certInfo.host

  let sslCertPath = path.join(certPath, 'fullchain.pem')
  let sslKeyPath = path.join(certPath, 'privkey.pem')
  let caPath = path.join(certPath, 'chain.pem')

  let context = tls.createSecureContext({
    cert: fs.readFileSync(sslCertPath),
    key: fs.readFileSync(sslKeyPath),
    ca: fs.readFileSync(caPath),
    minVersion: 'TLSv1.2'
  })

  if (certHost.startsWith('*.')) {
    let up = certHost.slice(2)
    if (!wildcards.includes(up)) wildcards.push(up)
    secureContexts[up] = context
  } else {
    secureContexts[certHost] = context
  }
}

function getSecureContext(hostname) {
  let up = hostname.slice(hostname.indexOf('.') + 1)
  if (wildcards.includes(up)) return secureContexts[up]

  return secureContexts[hostname]
}

function createSNICallback() {
  return (hostname, callback) => {
    callback(null, getSecureContext(hostname))
  }
}

function determineDestinationServer(req) {
  let host = req.headers.host || ''

  let destinationServer = availableServers.find(server => {
    return server.host === host ||
      (server.isWildcard && ('.' + host).endsWith(server.matches))
  })

  return destinationServer
}

function handleRequest(req, res) {
  let destinationServer = determineDestinationServer(req)

  if (destinationServer) {
    let proxyRequest = http.request({
      host: destinationServer.destination,
      port: destinationServer.port,
      path: req.url,
      method: req.method,
      headers: req.headers,
      timeout: 30 * 1000
    }, proxyResponse => {
      res.writeHead(proxyResponse.statusCode, proxyResponse.headers)
      proxyResponse.pipe(res)
    })

    req.pipe(proxyRequest)
  }
}

let httpServer = http.createServer()
let httpsServer = config.httpsPort ? https.createServer({
  SNICallback: createSNICallback()
}) : null

if (httpsServer) {
  config.servers.forEach(createSecureContext)

  httpServer.on('request', (req, res) => {
    let urlMatch
    if (urlMatch = req.url.match(/\/.well-known\/acme-challenge\/([^\/]*)/)) {
      let filePath = path.join(config.webrootPath, urlMatch[0])

      let stream = fs.createReadStream(filePath)
      stream.pipe(res)

      stream.on('error', err => {
        res.writeHead(404).end('404')
      })

      return
    }

    let redirectedURL = 'https://' + req.headers.host + req.url

    res.writeHead(308, { Location: redirectedURL })
    res.end()
  })
  httpServer.listen(config.httpPort)

  httpsServer.on('request', handleRequest)
  httpsServer.listen(config.httpsPort)
} else {
  httpServer.on('request', handleRequest)
  httpServer.listen(config.httpPort)
}
