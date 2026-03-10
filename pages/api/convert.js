const YAML = require("yaml");
const axios = require("axios");

// 检测字符串是否为 Base64 编码
function isBase64(str) {
  if (typeof str !== "string") return false;
  const trimmed = str.trim();
  // Base64 字符集校验，且长度是4的倍数（允许末尾=号）
  return /^[A-Za-z0-9+/\r\n]+=*$/.test(trimmed) && trimmed.length % 4 === 0;
}

// 解析 vmess:// URI（Base64 JSON 格式）
function parseVmessUri(uri) {
  try {
    const b64 = uri.replace("vmess://", "");
    const json = JSON.parse(Buffer.from(b64, "base64").toString("utf-8"));
    const proxy = {
      name: json.ps || json.add,
      type: "vmess",
      server: json.add,
      port: Number.parseInt(json.port),
      uuid: json.id,
      alterId: Number.parseInt(json.aid) || 0,
      cipher: "auto",
      udp: true,
    };
    if (json.net === "ws") {
      proxy.network = "ws";
      if (json.path) proxy["ws-path"] = json.path;
      if (json.host) proxy["ws-headers"] = { Host: json.host };
    }
    if (json.tls === "tls") {
      proxy.tls = true;
      if (json.sni) proxy.servername = json.sni;
    }
    return proxy;
  } catch (e) {
    return null;
  }
}

// 解析 trojan:// URI
function parseTrojanUri(uri) {
  try {
    const url = new URL(uri);
    const params = url.searchParams;
    const proxy = {
      name: decodeURIComponent(url.hash.slice(1)) || url.hostname,
      type: "trojan",
      server: url.hostname,
      port: Number.parseInt(url.port),
      password: decodeURIComponent(url.username),
      udp: true,
    };
    if (params.get("sni")) proxy.sni = params.get("sni");
    if (params.get("peer")) proxy.sni = params.get("peer");
    if (params.get("allowInsecure") === "1" || params.get("allowInsecure") === "true") {
      proxy["skip-cert-verify"] = true;
    }
    const network = params.get("type");
    if (network === "ws") {
      proxy.network = "ws";
      if (params.get("path")) proxy["ws-path"] = params.get("path");
      if (params.get("host")) proxy["ws-headers"] = { Host: params.get("host") };
    } else if (network === "grpc") {
      proxy.network = "grpc";
      if (params.get("serviceName")) proxy["grpc-opts"] = { "grpc-service-name": params.get("serviceName") };
    }
    return proxy;
  } catch (e) {
    return null;
  }
}

// 解析 vless:// URI
function parseVlessUri(uri) {
  try {
    const url = new URL(uri);
    const params = url.searchParams;
    const proxy = {
      name: decodeURIComponent(url.hash.slice(1)) || url.hostname,
      type: "vless",
      server: url.hostname,
      port: Number.parseInt(url.port),
      uuid: decodeURIComponent(url.username),
      udp: true,
    };
    const security = params.get("security");
    if (security === "tls" || security === "xtls") {
      proxy.tls = true;
      if (params.get("sni")) proxy.servername = params.get("sni");
      if (params.get("allowInsecure") === "1") proxy["skip-cert-verify"] = true;
    }
    const flow = params.get("flow");
    if (flow) proxy.flow = flow;
    const network = params.get("type");
    if (network === "ws") {
      proxy.network = "ws";
      if (params.get("path")) proxy["ws-path"] = params.get("path");
      if (params.get("host")) proxy["ws-headers"] = { Host: params.get("host") };
    } else if (network === "grpc") {
      proxy.network = "grpc";
      if (params.get("serviceName")) proxy["grpc-opts"] = { "grpc-service-name": params.get("serviceName") };
    }
    return proxy;
  } catch (e) {
    return null;
  }
}

// 解析 ss:// URI
function parseSsUri(uri) {
  try {
    const url = new URL(uri);
    const name = decodeURIComponent(url.hash.slice(1)) || url.hostname;
    // ss://BASE64@host:port 或 ss://BASE64(method:password)@host:port
    let method;
    let password;
    if (url.username && url.password) {
      method = decodeURIComponent(url.username);
      password = decodeURIComponent(url.password);
    } else if (url.username) {
      // userinfo 是 base64(method:password)
      const decoded = Buffer.from(url.username, "base64").toString("utf-8");
      const colonIdx = decoded.indexOf(":");
      method = decoded.slice(0, colonIdx);
      password = decoded.slice(colonIdx + 1);
    }
    return {
      name,
      type: "ss",
      server: url.hostname,
      port: Number.parseInt(url.port),
      cipher: method,
      password,
      udp: true,
    };
  } catch (e) {
    return null;
  }
}

// 将 Base64 URI 列表解析为 Clash proxies 数组
function parseUriList(content) {
  const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const proxies = [];
  for (const line of lines) {
    let proxy = null;
    if (line.startsWith("vmess://")) {
      proxy = parseVmessUri(line);
    } else if (line.startsWith("trojan://")) {
      proxy = parseTrojanUri(line);
    } else if (line.startsWith("vless://")) {
      proxy = parseVlessUri(line);
    } else if (line.startsWith("ss://")) {
      proxy = parseSsUri(line);
    }
    if (proxy) proxies.push(proxy);
    else if (line) console.log(`Skip unsupported URI: ${line.slice(0, 30)}...`);
  }
  return proxies;
}

module.exports = async (req, res) => {
  const url = req.query.url;
  const target = req.query.target;
  console.log(`query: ${JSON.stringify(req.query)}`);
  if (url === undefined) {
    res.status(400).send("Missing parameter: url");
    return;
  }

  console.log(`Fetching url: ${url}`);
  let configFile = null;
  try {
    const result = await axios({
      url,
      headers: {
        "User-Agent":
          "ClashX Pro/1.72.0.4 (com.west2online.ClashXPro; build:1.72.0.4; macOS 12.0.1) Alamofire/5.4.4",
      },
    });
    configFile = result.data;
  } catch (error) {
    res.status(400).send(`Unable to get url, error: ${error}`);
    return;
  }

  // 如果 axios 已经自动解析为对象（YAML/JSON），转回字符串
  if (typeof configFile === "object") {
    configFile = YAML.stringify(configFile);
  }

  let proxies = null;

  // 尝试1：标准 YAML 格式（完整 Clash 配置或 proxy-provider 格式）
  try {
    const config = YAML.parse(configFile);
    if (config && Array.isArray(config.proxies) && config.proxies.length > 0) {
      console.log(`👌 Parsed as YAML Clash config, ${config.proxies.length} proxies`);
      proxies = config.proxies;
    }
  } catch (e) {
    // 不是 YAML，继续尝试其他格式
  }

  // 尝试2：Base64 编码的 URI 列表
  if (!proxies) {
    const trimmed = (typeof configFile === "string" ? configFile : "").trim();
    if (isBase64(trimmed)) {
      try {
        const decoded = Buffer.from(trimmed, "base64").toString("utf-8");
        console.log("👌 Detected Base64 content, decoding...");
        const parsed = parseUriList(decoded);
        if (parsed.length > 0) {
          console.log(`👌 Parsed ${parsed.length} proxies from Base64 URI list`);
          proxies = parsed;
        }
      } catch (e) {
        console.log(`Failed to decode Base64: ${e}`);
      }
    }
  }

  // 尝试3：直接是 URI 列表（未经 Base64 编码）
  if (!proxies) {
    const trimmed = (typeof configFile === "string" ? configFile : "").trim();
    if (
      trimmed.startsWith("vmess://") ||
      trimmed.startsWith("trojan://") ||
      trimmed.startsWith("vless://") ||
      trimmed.startsWith("ss://")
    ) {
      const parsed = parseUriList(trimmed);
      if (parsed.length > 0) {
        console.log(`👌 Parsed ${parsed.length} proxies from plain URI list`);
        proxies = parsed;
      }
    }
  }

  if (!proxies || proxies.length === 0) {
    res.status(400).send("No proxies found in this config (tried YAML, Base64 URI list, plain URI list)");
    return;
  }

  if (target === "surge") {
    const supportedProxies = proxies.filter((proxy) =>
      ["ss", "vmess", "trojan"].includes(proxy.type)
    );
    const surgeProxies = supportedProxies.map((proxy) => {
      console.log(proxy.server);
      const common = `${proxy.name} = ${proxy.type}, ${proxy.server}, ${proxy.port}`;
      if (proxy.type === "ss") {
        // ProxySS = ss, example.com, 2021, encrypt-method=xchacha20-ietf-poly1305, password=12345, obfs=http, obfs-host=example.com, udp-relay=true
        if (proxy.plugin === "v2ray-plugin") {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge does not support Shadowsocks with v2ray-plugin`
          );
          return;
        }
        let result = `${common}, encrypt-method=${proxy.cipher}, password=${proxy.password}`;
        if (proxy.plugin === "obfs") {
          const mode = proxy?.["plugin-opts"].mode;
          const host = proxy?.["plugin-opts"].host;
          result = `${result}, obfs=${mode}${
            host ? `, obfs-host=example.com ${host}` : ""
          }`;
        }
        if (proxy.udp) {
          result = `${result}, udp-relay=${proxy.udp}`;
        }
        return result;
      }
      if (proxy.type === "vmess") {
        // ProxyVmess = vmess, example.com, 2021, username=0233d11c-15a4-47d3-ade3-48ffca0ce119, skip-cert-verify=true, sni=example.com, tls=true, ws=true, ws-path=/path
        if (["h2", "http", "grpc"].includes(proxy.network)) {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge probably doesn't support Vmess(${proxy.network})`
          );
          return;
        }
        let result = `${common}, username=${proxy.uuid}`;
        if (proxy["skip-cert-verify"]) {
          result = `${result}, skip-cert-verify=${proxy["skip-cert-verify"]}`;
        }
        if (proxy.servername) {
          result = `${result}, sni=${proxy.servername}`;
        }
        if (proxy.tls) {
          result = `${result}, tls=${proxy.tls}`;
        }
        if (proxy.network === "ws") {
          result = `${result}, ws=true`;
        }
        if (proxy["ws-path"]) {
          result = `${result}, ws-path=${proxy["ws-path"]}`;
        }
        return result;
      }
      if (proxy.type === "trojan") {
        // ProxyTrojan = trojan, example.com, 2021, username=user, password=12345, skip-cert-verify=true, sni=example.com
        if (["grpc"].includes(proxy.network)) {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge probably doesn't support Trojan(${proxy.network})`
          );
          return;
        }
        let result = `${common}, password=${proxy.password}`;
        if (proxy["skip-cert-verify"]) {
          result = `${result}, skip-cert-verify=${proxy["skip-cert-verify"]}`;
        }
        if (proxy.sni) {
          result = `${result}, sni=${proxy.sni}`;
        }
        return result;
      }
    });
    const filteredProxies = surgeProxies.filter((p) => p !== undefined);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(filteredProxies.join("\n"));
  } else {
    const response = YAML.stringify({ proxies });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(response);
  }
};