import http from 'http'
import https from 'https'
import tls from 'tls'
import fs from 'fs/promises'
import { createReadStream } from 'fs'
import path from 'path'
import url from 'url'
import config from './config.json' with { type: 'json' }
import { WebSocket, WebSocketServer, createWebSocketStream } from 'ws'
import { getLoadAverages, hasHighLoadAvg } from './monitor-server.mjs'
import { spawn } from 'child_process'

let MAX_RESPONSE_COUNTS = 50

let availableServers = config.servers.map(server => {
  server.responseTimes = []

  if (server.host.startsWith('*')) {
    server.isWildcard = true
    server.matches = server.host.slice(2)

    return server
  } else return server
})

let secureContexts = {}
let wildcards = []

async function createSecureContext(certInfo) {
  try {
    let certPath = certInfo.sslCertPath
    let certHost = certInfo.host

    let sslCertPath = path.join(certPath, 'fullchain.pem')
    let sslKeyPath = path.join(certPath, 'privkey.pem')
    let caPath = path.join(certPath, 'chain.pem')

    let context = tls.createSecureContext({
      cert: await fs.readFile(sslCertPath),
      key: await fs.readFile(sslKeyPath),
      ca: await fs.readFile(caPath),
      minVersion: 'TLSv1.2'
    })

    if (certHost.startsWith('*.')) {
      let up = certHost.slice(2)
      if (!wildcards.includes(up)) wildcards.push(up)
      secureContexts[up] = context
    } else {
      secureContexts[certHost] = context
    }
  } catch (e) {
    console.log('Registration for', certInfo.host, 'failed');
    console.log(e);
    certInfo.failed = true
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

  if (!destinationServer || destinationServer.failed) return null

  return destinationServer
}

function logRequestTime(server, time) {
  let duration = new Date() - time
  server.responseTimes = [...server.responseTimes.slice(1 - MAX_RESPONSE_COUNTS), duration]
}

function getServerAverage(server) {
  return {
    ...server,
    average: server.responseTimes.length === 0 ? 0 : server.responseTimes.reduce((a, b) => a + b, 0) / server.responseTimes.length
  }
}

function getServerAverages() {
  return availableServers.map(getServerAverage)
}

function resetServerAverages() {
  availableServers.forEach(server => server.responseTimes = [])
}

function handleSiteResponse(server, res) {
  let { average } = getServerAverage(server)

  res.writeHead(200, { 'content-type': 'application/json' })
  res.end(JSON.stringify({
    host: server.host,
    average: parseFloat(average.toFixed(3))
  }))
}

function handleRequest(req, res) {
  if (req.ended) return

  let startTime = new Date()

  let destinationServer = determineDestinationServer(req)

  if (destinationServer) {
    if (req.url === '/.host-proxy/site-response') return handleSiteResponse(destinationServer, res)

    let headers = {}

    let excludedHeaders = destinationServer.dropHeaders || []
    for (let headerName of Object.keys(req.headers)) {
      if (!excludedHeaders.includes(headerName)) headers[headerName] = req.headers[headerName]
    }

    if (req.connection.remoteAddress) headers['x-forwarded-for'] = req.connection.remoteAddress

    let proxyRequest = (destinationServer.useHTTPS ? https : http).request({
      host: destinationServer.destination,
      port: destinationServer.port,
      path: req.url,
      method: req.method,
      headers,
      timeout: 30 * 1000
    }, proxyResponse => {
      res.writeHead(proxyResponse.statusCode, proxyResponse.headers)
      proxyResponse.pipe(res)

      res.on('close', () => {
        if (!req.url.startsWith('/static/')) logRequestTime(destinationServer, startTime)
      })
    })

    proxyRequest.on('error', error => {
      res.writeHead(503)
      res.end('Error: Could not proxy request to server')
    })

    req.pipe(proxyRequest)
  }
}

let httpServer = http.createServer()
let httpsServer = config.httpsPort ? https.createServer({
  SNICallback: createSNICallback()
}) : null

function handleWebroot(req, res) {
  if (req.url.match(/\/.well-known\/acme-challenge\/[^\/]*/)) {
    let filePath = path.join(config.webrootPath, req.url)

    let stream = createReadStream(filePath)

    stream.on('open', () => {
      res.writeHead(200)
      stream.pipe(res)
    })
    
    stream.on('error', err => {
      res.writeHead(404).end('404')
    })
    
    return req.ended = true
  }
}

httpServer.on('request', handleWebroot)

if (httpsServer) {
  if (config.enforceHTTPS) {
    httpServer.on('request', (req, res) => {
      if (req.ended) return

      let redirectedURL = 'https://' + req.headers.host + req.url

      res.writeHead(308, { Location: redirectedURL })
      res.end()
    })
  } else {
    httpServer.on('request', handleRequest)
  }

  config.servers.forEach(createSecureContext)

  httpServer.listen(config.httpPort)

  httpsServer.on('request', handleWebroot)
  httpsServer.on('request', handleRequest)
  httpsServer.listen(config.httpsPort)
} else {
  httpServer.on('request', handleRequest)
  httpServer.listen(config.httpPort)
}

let websocketServer = new WebSocketServer({ noServer: true })
let server = httpsServer || httpServer
server.on('upgrade', (req, socket, head) => {
  let pathname = url.parse(req.url).pathname
  let destinationServer = determineDestinationServer(req)

  let proxyWS = new WebSocket(`ws://${destinationServer.destination}:${destinationServer.port}${pathname}`, {
    headers: req.headers
  })

  proxyWS.on('open', () => {
    websocketServer.handleUpgrade(req, socket, head, ws => {
      let proxyStream = createWebSocketStream(proxyWS, { encoding: 'utf8' });
      let wsStream = createWebSocketStream(ws, { encoding: 'utf8' });

      proxyStream.pipe(wsStream)
      wsStream.pipe(proxyStream)

      ws.isAlive = true
      ws.on('pong', () => ws.isAlive = true)
    })
  })

  proxyWS.on('error', () => socket.destroy())
  proxyWS.on('close', () => socket.destroy())
})

setInterval(() => {
  websocketServer.clients.forEach(ws => {
    if (!ws.isAlive) return ws.terminate()

    ws.isAlive = false
    ws.ping()
  })
}, 1000 * 30)

try {
  let hadSlowServer = false
  await getLoadAverages()
  setTimeout(() => {
    resetServerAverages()
    setInterval(async () => {
      let slowServer = getServerAverages().find(sever => sever.average >= 3000)
      let hasSlowServer = !!slowServer
      if (hasSlowServer && hadSlowServer && await hasHighLoadAvg()) {
        console.log('Slow server & high load avg', slowServer)
        spawn('sudo', ['reboot'])
      }
      hadSlowServer = hasSlowServer
      resetServerAverages()
    }, 1000 * 60)
  }, 1000 * 60 * 1.5)
} catch (e) {
}