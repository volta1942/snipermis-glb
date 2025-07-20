"use strict";

process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";

const tls = require("node:tls");
const dns = require("node:dns").promises;
const WebSocket = require("ws");
const fs = require("fs");
const { watchFile } = require("fs");
const extractJson = require("extract-json-from-string");

const token = "";
const server = "";
const sockets = 2;

const guilds = new Map();
const socketPool = [];
let lastSequence = null;
let resolvedIP = null;
let mfaToken, websocket, vanity;

process.nextTick(() => {
    process.title = 'Sniper';
    if (process.platform !== 'win32') {
        try {
            require('os').setPriority(0, require('os').constants.PRIORITY_HIGH);
        } catch (e) {}
    }
});

async function resolveHost() {
    const addresses = await dns.resolve4("canary.discord.com");
    resolvedIP = addresses[0]; 
    console.log(`Resolved canary.discord.com to ${resolvedIP}`);
}

const buildRequest = (code) => {
    const body = `{"code":"${code}"}`;
    const contentLength = Buffer.byteLength(body);
    return `PATCH /api/v7/guilds/${server}/vanity-url HTTP/1.1\r\nHost: canary.discord.com\r\nAuthorization: ${token}\r\nX-Discord-MFA-Authorization: ${mfaToken}\r\nContent-Type: application/json\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nX-Super-Properties: eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzU1NjI0fQ==\r\nContent-Length: ${contentLength}\r\nConnection: keep-alive\r\n\r\n${body}`;
};

async function watcher() {
  const update = async () => {
      const content = await fs.promises.readFile("mfa_token.txt", "utf-8");
      mfaToken = content.trim();
  };
  await update();
  watchFile("mfa_token.txt", { interval: 250 }, async () => { await update(); });
}

function executeSnipe(vanityCode) {
    const request = buildRequest(vanityCode);
    process.nextTick(() => { 
		socketPool[0].write(request); 
		socketPool[1].write(request); 
	});
}

const parseMessage = (data) => {
        if (data.includes('"GUILD_UPDATE"')) {
            return JSON.parse(data);
        }
        
        const opMatch = /"op":(\d+)/.exec(data);
        const tMatch = /"t":"([^"]+)"/.exec(data);
        
        if (opMatch) {
            const result = { op: parseInt(opMatch[1]) };
            if (tMatch) result.t = tMatch[1];
            
            if (tMatch && tMatch[1] === "READY") {
                return JSON.parse(data);
            }
            
            if (result.op === 11) {
                const seqMatch = /"s":(\d+)/.exec(data);
                if (seqMatch) lastSequence = parseInt(seqMatch[1]);
            }
            
            return result;
        }
};

async function initializeSocketPool() {
    await resolveHost();
    
    const promises = [];
    for (let i = 0; i < sockets; i++) {
        const promise = new Promise((resolve) => {
            const socket = tls.connect({
                host: resolvedIP,
                port: 443,
            });

            socket.setNoDelay(true);
            socket.setKeepAlive(true, 300);
            socket.setTimeout(0);

            socket.on("secureConnect", () => {
                socketPool.push(socket);
                if (socketPool.length === 1) { setupWebSocket(); }
                resolve();
            });

            socket.on("data", (data) => {
                const ext = extractJson(data.toString());
                const find = ext.find((e) => e.code || e.message);
                if (find) { console.log(find); }
            });

            socket.on("error", () => { process.exit(0); });
            socket.on("close", () => { process.exit(0); });
        });

        promises.push(promise);
    }

    await Promise.allSettled(promises);
    setInterval(() => { 
        socketPool.forEach(socket => { 
            socket.write(`GET /api/v10/gateway HTTP/1.1\r\nHost: canary.discord.com\r\nAuthorization: ${token}\r\nConnection: keep-alive\r\n\r\n`); 
        }); 
    }, 600);
}

function setupWebSocket() {
    const wsOptions = {
        perMessageDeflate: false,
        handshakeTimeout: 5000,
        skipUTF8Validation: true, 
    };
    
    websocket = new WebSocket("wss://gateway-us-east1-b.discord.gg/?v=10&encoding=json", wsOptions);
    
    websocket.binaryType = 'arraybuffer';
    
    websocket.onopen = () => {};
    websocket.onclose = () => { process.exit(0); };
    websocket.onerror = () => { process.exit(0); };
    
    websocket.onmessage = (message) => {
        const messageData = message.data.toString();
        const parsed = parseMessage(messageData);
        
        if (!parsed) return;
        
        const { d, op, t } = parsed;

        if (t === "GUILD_UPDATE") {
            const find = guilds.get(d.id);
            if (find && find !== d.vanity_url_code) {
                executeSnipe(find);
                vanity = `${find}`;
            }
            return; 
        }

        if (t === "READY") { 
            d.guilds.forEach(({ id, vanity_url_code }) => { 
                if (vanity_url_code) guilds.set(id, vanity_url_code); 
            }); 
            console.log(guilds); 
        }

        if (op === 10) {
            websocket.send(JSON.stringify({
                op: 2,
                d: { 
                    token: token, 
                    intents: 1, 
                    properties: { os: "Windows", browser: "Chrome", device: "Desktop" } 
                }
            }));
            
            
            setInterval(() => { 
                websocket.send(JSON.stringify({ op: 1, d: lastSequence })); 
            }, 30000);
        }

        if (parsed.s) { lastSequence = parsed.s; }
    };
}

async function initialize() {
    await initializeSocketPool();
    await watcher();
}

initialize();