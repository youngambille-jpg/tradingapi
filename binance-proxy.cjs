const { createHmac, createPublicKey, verify } = require('node:crypto');
const { request: httpsRequest } = require('node:https');
const { Resolver } = require('node:dns/promises');
const { lookup: systemLookup } = require('node:dns');

const BINANCE_HOST = 'web3.binance.com';
const CHAIN_ID = '56';
const RWA_TOKENS_PATH = '/api/v1/dex/market/rwa/tokens';
const RWA_PRICE_PATH = '/api/v1/dex/market/rwa/price';
const RWA_PORTFOLIO_PNL_PATH = '/api/v1/dex/market/portfolio/recent-pnl';
const TRADING_PATH = '/api/v1/dex/aggregator';
const TRANSACTION_PATH = '/api/v1/dex/pre-transaction';
const REQUEST_TIMEOUT_MS = 20000;
let privyKeysCache = { expiresAt: 0, keys: [] };
let langChainModules;

const publicResolver = new Resolver();
publicResolver.setServers(['1.1.1.1', '8.8.8.8']);

function publicLookup(hostname, options, callback) {
  publicResolver
    .resolve4(hostname)
    .then((addresses) => {
      if (!addresses.length) throw new Error(`No IPv4 addresses found for ${hostname}.`);
      if (options?.all) {
        callback(null, addresses.map((address) => ({ address, family: 4 })));
      } else {
        callback(null, addresses[0], 4);
      }
    })
    .catch(() => systemLookup(hostname, options, callback));
}

function buildQuery(params) {
  return Object.entries(params)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
    .join('&');
}

async function signedGet(path, params, dataType = 'array') {
  return signedRequest('GET', path, params, undefined, dataType);
}

async function signedRequest(method, path, params, body, dataType = 'any') {
  const apiKey = process.env.BINANCE_WEB3_API_KEY;
  const secretKey = process.env.BINANCE_WEB3_SECRET_KEY;
  if (!apiKey || !secretKey) {
    const error = new Error('Binance Web3 API credentials are not configured on the server.');
    error.statusCode = 503;
    throw error;
  }

  const query = buildQuery(params);
  const requestPath = `/build${path}${query ? `?${query}` : ''}`;
  const timestamp = new Date().toISOString();
  const bodyText = body === undefined ? '' : JSON.stringify(body);
  const signature = createHmac('sha256', secretKey)
    .update(`${timestamp}${method}${requestPath}${bodyText}`, 'utf8')
    .digest('base64');
  const response = await new Promise((resolve, reject) => {
    const request = httpsRequest(
      {
        hostname: BINANCE_HOST,
        path: requestPath,
        method,
        lookup: publicLookup,
        headers: {
          'X-OC-APIKEY': apiKey,
          'X-OC-TIMESTAMP': timestamp,
          'X-OC-SIGN': signature,
          'X-OC-RECV-WINDOW': '5000',
          ...(body === undefined ? {} : {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(bodyText),
          }),
        },
      },
      (incomingResponse) => {
        let body = '';
        incomingResponse.setEncoding('utf8');
        incomingResponse.on('data', (chunk) => {
          body += chunk;
        });
        incomingResponse.on('end', () => {
          resolve({ statusCode: incomingResponse.statusCode, body });
        });
        incomingResponse.on('error', reject);
      },
    );

    const timeout = setTimeout(() => {
      request.destroy(new Error(`Binance request timed out after ${REQUEST_TIMEOUT_MS / 1000}s.`));
    }, REQUEST_TIMEOUT_MS);
    request.on('close', () => clearTimeout(timeout));
    request.on('error', reject);
    if (body !== undefined) request.write(bodyText);
    request.end();
  });

  let payload;
  try {
    payload = JSON.parse(response.body);
  } catch {
    payload = null;
  }

  const validData = dataType === 'array'
    ? Array.isArray(payload?.data)
    : dataType === 'object'
      ? payload?.data !== null && typeof payload?.data === 'object'
        && !Array.isArray(payload.data)
      : payload?.data !== undefined && payload.data !== null;
  if (response.statusCode < 200 || response.statusCode >= 300
    || !payload || Number(payload.code) !== 0 || !validData) {
    const error = new Error(
      payload?.msg || `Binance Web3 request failed (${response.statusCode || 'invalid response'}).`,
    );
    error.statusCode = response.statusCode >= 500
      ? 502
      : response.statusCode >= 400
        ? response.statusCode
        : 502;
    throw error;
  }
  return payload.data;
}

function isAddress(value) {
  return typeof value === 'string' && /^0x[a-fA-F0-9]{40}$/.test(value);
}

function integerString(value, label) {
  try {
    const parsed = typeof value === 'string' && /^0x[0-9a-f]+$/i.test(value)
      ? BigInt(value)
      : BigInt(String(value));
    if (parsed < 0n) throw new Error('negative');
    return parsed.toString(10);
  } catch {
    const error = new Error(`${label} must be a non-negative integer.`);
    error.statusCode = 400;
    throw error;
  }
}

async function readJson(request) {
  let raw = '';
  for await (const chunk of request) {
    raw += chunk;
    if (Buffer.byteLength(raw) > 64 * 1024) {
      const error = new Error('Request body is too large.');
      error.statusCode = 413;
      throw error;
    }
  }

  try {
    return JSON.parse(raw || '{}');
  } catch {
    const error = new Error('Request body must be valid JSON.');
    error.statusCode = 400;
    throw error;
  }
}

async function privyJwks(appId) {
  if (privyKeysCache.expiresAt > Date.now() && privyKeysCache.keys.length) {
    return privyKeysCache.keys;
  }

  const response = await fetch(
    `https://auth.privy.io/api/v1/apps/${encodeURIComponent(appId)}/jwks.json`,
    { signal: AbortSignal.timeout(8000) },
  );
  if (!response.ok) throw new Error('Unable to load Privy authentication keys.');

  const payload = await response.json();
  if (!Array.isArray(payload.keys) || payload.keys.length === 0) {
    throw new Error('Privy authentication keys are unavailable.');
  }
  privyKeysCache = { expiresAt: Date.now() + 10 * 60 * 1000, keys: payload.keys };
  return payload.keys;
}

async function requirePrivy(request) {
  const appId = process.env.PRIVY_APP_ID || process.env.EXPO_PUBLIC_PRIVY_APP_ID;
  if (!appId) {
    const error = new Error('Privy server verification is not configured. Set PRIVY_APP_ID on the server.');
    error.statusCode = 503;
    throw error;
  }

  const token = String(request.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const parts = token.split('.');
  if (parts.length !== 3) {
    const error = new Error('Sign in with Privy to trade.');
    error.statusCode = 401;
    throw error;
  }

  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const key = (await privyJwks(appId)).find((item) => item.kid === header.kid);
    const signature = Buffer.from(parts[2], 'base64url');
    const valid = header.alg === 'ES256' && key && verify(
      'sha256',
      Buffer.from(`${parts[0]}.${parts[1]}`),
      { key: createPublicKey({ key, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
      signature,
    );
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!valid || !audiences.includes(appId)
      || !['privy.io', 'https://auth.privy.io'].includes(claims.iss)
      || !claims.sub || Number(claims.exp) <= Date.now() / 1000) {
      throw new Error('Invalid or expired Privy session. Sign in again to continue.');
    }
    return claims;
  } catch (error) {
    const authError = new Error(
      error?.statusCode ? error.message : 'Invalid or expired Privy session. Sign in again to continue.',
    );
    authError.statusCode = error?.statusCode || 401;
    throw authError;
  }
}

function required(value, label) {
  if (value === undefined || value === null || String(value) === '') {
    const error = new Error(`${label} is required.`);
    error.statusCode = 400;
    throw error;
  }
  return String(value);
}

function asData(data) {
  return Array.isArray(data) ? data[0] || {} : data || {};
}

function compactPosition(value, depth = 0) {
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.slice(0, 300);
  if (depth >= 3) return '[nested data omitted]';
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => compactPosition(item, depth + 1));
  if (typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).slice(0, 40)
        .map(([key, item]) => [key, compactPosition(item, depth + 1)]),
    );
  }
  return String(value);
}

async function handleAiChat(request, response) {
  if (request.method !== 'POST') {
    sendJson(response, 405, { error: 'Method not allowed.' });
    return true;
  }

  try {
    await requirePrivy(request);
    const apiKey = process.env.OPENROUTER_API_KEY;
    if (!apiKey) {
      const error = new Error('AI chat is not configured. Set OPENROUTER_API_KEY on the server.');
      error.statusCode = 503;
      throw error;
    }

    const body = await readJson(request);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      throw Object.assign(new Error('The request body must be a JSON object.'), { statusCode: 400 });
    }
    const walletAddress = body.walletAddress == null ? '' : String(body.walletAddress);
    if (walletAddress && !isAddress(walletAddress)) {
      throw Object.assign(new Error('A valid BNB Smart Chain wallet address is required.'), { statusCode: 400 });
    }

    const inputMessages = Array.isArray(body.messages)
      ? body.messages
      : typeof body.message === 'string'
        ? [{ role: 'user', content: body.message }]
        : [];
    if (!inputMessages.length || inputMessages.length > 12) {
      throw Object.assign(new Error('Provide between 1 and 12 chat messages.'), { statusCode: 400 });
    }

    let totalCharacters = 0;
    const chatMessages = inputMessages.map((item) => {
      if (!item || !['user', 'assistant'].includes(item.role)
        || typeof item.content !== 'string' || !item.content.trim()) {
        throw Object.assign(
          new Error('Messages must contain non-empty user or assistant text.'),
          { statusCode: 400 },
        );
      }
      totalCharacters += item.content.length;
      if (item.content.length > 4000 || totalCharacters > 12000) {
        throw Object.assign(new Error('Chat history exceeds the allowed length.'), { statusCode: 413 });
      }
      return item.role === 'user'
        ? { role: 'user', content: item.content }
        : { role: 'assistant', content: item.content };
    });
    if (chatMessages[chatMessages.length - 1].role !== 'user') {
      throw Object.assign(new Error('The latest chat message must be from the user.'), { statusCode: 400 });
    }

    if (!langChainModules) {
      langChainModules = Promise.all([
        import('@langchain/openai'),
        import('@langchain/core/tools'),
        import('@langchain/core/messages'),
        import('zod'),
      ]).then(([openai, tools, messages, zod]) => ({
        ChatOpenAI: openai.ChatOpenAI,
        tool: tools.tool,
        SystemMessage: messages.SystemMessage,
        HumanMessage: messages.HumanMessage,
        AIMessage: messages.AIMessage,
        ToolMessage: messages.ToolMessage,
        z: zod.z,
      })).catch((error) => {
        langChainModules = undefined;
        throw error;
      });
    }
    const { ChatOpenAI, tool, SystemMessage, HumanMessage, AIMessage, ToolMessage, z } = await langChainModules;
    const availableTools = [
      tool(async ({ query }) => {
        const markets = await getRwaMarkets();
        const normalizedQuery = (query || '').trim().toLowerCase();
        const matches = normalizedQuery
          ? markets.filter((market) =>
            `${market.ticker} ${market.symbol} ${market.name} ${market.provider}`
              .toLowerCase().includes(normalizedQuery))
          : markets;
        return JSON.stringify({
          count: matches.length,
          markets: matches.slice(0, 25),
          truncated: matches.length > 25,
        });
      }, {
        name: 'search_stock_markets',
        description: 'Look up current Binance tokenized-equity stock prices and trading status. Use a ticker or company-name query to filter.',
        schema: z.object({ query: z.string().max(80).optional() }),
      }),
      tool(async () => {
        if (!walletAddress) {
          return JSON.stringify({ error: 'No wallet address was supplied. Ask the user for a BNB Smart Chain wallet address and retry.' });
        }
        const positions = await getRwaPortfolio(walletAddress.toLowerCase());
        return JSON.stringify({
          walletAddress: walletAddress.toLowerCase(),
          positionCount: positions.length,
          positions: positions.slice(0, 50).map((position) => compactPosition(position)),
          truncated: positions.length > 50,
        });
      }, {
        name: 'get_user_stock_holdings',
        description: 'Retrieve Binance RWA portfolio positions and PnL for the wallet address supplied with this authenticated chat request.',
        schema: z.object({}),
      }),
    ];

    const model = new ChatOpenAI({
      model: process.env.OPENROUTER_MODEL || 'apodex/apodex-1.1-mini:free',
      apiKey,
      temperature: 0.2,
      timeout: 30000,
      maxRetries: 1,
      configuration: {
        baseURL: 'https://openrouter.ai/api/v1',
        defaultHeaders: {
          'HTTP-Referer': 'http://localhost',
          'X-Title': 'Trading Assistant',
        },
      },
    }).bindTools(availableTools);

    const messages = [
      new SystemMessage(
        'You are an informational assistant for tokenized equities on BNB Smart Chain. ' +
        'Use the market and holdings tools whenever the question depends on current prices, market status, or portfolio positions. ' +
        'Never invent live data; distinguish unavailable data from zero values. ' +
        'Summarize retrieved data clearly and do not claim to execute trades or provide personalized financial advice.',
      ),
      ...chatMessages.map((item) => item.role === 'user'
        ? new HumanMessage(item.content)
        : new AIMessage(item.content)),
    ];
    const toolsByName = new Map(availableTools.map((availableTool) => [availableTool.name, availableTool]));
    let callsMade = 0;

    for (let iteration = 0; iteration < 4; iteration += 1) {
      const assistantMessage = await model.invoke(messages);
      messages.push(assistantMessage);
      const toolCalls = assistantMessage.tool_calls || [];
      if (!toolCalls.length) {
        const answer = typeof assistantMessage.content === 'string'
          ? assistantMessage.content
          : Array.isArray(assistantMessage.content)
            ? assistantMessage.content
              .filter((part) => part && typeof part.text === 'string')
              .map((part) => part.text)
              .join('')
            : '';
        if (!answer.trim()) throw new Error('The AI provider returned an empty response.');
        sendJson(response, 200, { source: 'openrouter', message: answer });
        return true;
      }

      callsMade += toolCalls.length;
      if (callsMade > 6) throw new Error('The AI requested too many data lookups. Please narrow the question.');
      const results = await Promise.all(toolCalls.map(async (toolCall) => {
        const selectedTool = toolsByName.get(toolCall.name);
        if (!selectedTool) throw new Error('The AI requested an unsupported data lookup.');
        const result = await selectedTool.invoke(toolCall.args || {});
        return new ToolMessage({
          content: typeof result === 'string' ? result : JSON.stringify(result),
          tool_call_id: toolCall.id,
        });
      }));
      messages.push(...results);
    }
    throw new Error('The AI could not complete the request within the tool-call limit.');
  } catch (error) {
    sendJson(response, Number(error?.statusCode) || 502, {
      error: error?.message || 'AI chat is unavailable.',
    });
  }
  return true;
}

async function handleTradingRoute(request, response, requestUrl) {
  const route = requestUrl.pathname.slice('/api/binance/trading/'.length);
  const query = requestUrl.searchParams;
  const postRoutes = ['quote', 'swap', 'approve', 'simulate', 'broadcast', 'rfq-submit'];
  const getRoutes = ['rfq-status', 'status'];
  if (!postRoutes.includes(route) && !getRoutes.includes(route)) return false;

  const expectedMethod = postRoutes.includes(route) ? 'POST' : 'GET';
  if (request.method !== expectedMethod) {
    sendJson(response, 405, { error: 'Method not allowed.' });
    return true;
  }

  try {
    await requirePrivy(request);
    const body = postRoutes.includes(route) ? await readJson(request) : {};
    let data;

    if (route === 'quote') {
      const walletAddress = required(body.walletAddress, 'walletAddress');
      if (!isAddress(walletAddress)) {
        throw Object.assign(new Error('A valid BNB Smart Chain wallet address is required.'), { statusCode: 400 });
      }
      const amount = required(body.amount, 'amount');
      if (!/^\d+$/.test(amount) || BigInt(amount) <= 0n) {
        throw Object.assign(new Error('Amount must be a positive integer in token base units.'), { statusCode: 400 });
      }
      const fromTokenAddress = required(body.fromTokenAddress, 'fromTokenAddress');
      const toTokenAddress = required(body.toTokenAddress, 'toTokenAddress');
      if (!isAddress(fromTokenAddress) || !isAddress(toTokenAddress)
        || fromTokenAddress.toLowerCase() === toTokenAddress.toLowerCase()) {
        throw Object.assign(
          new Error('Choose two different valid BNB Chain token contracts.'),
          { statusCode: 400 },
        );
      }
      data = await signedGet(`${TRADING_PATH}/quote`, {
        binanceChainId: CHAIN_ID,
        amount,
        fromTokenAddress,
        toTokenAddress,
        userWalletAddress: walletAddress,
      }, 'any');
    } else if (route === 'swap') {
      const walletAddress = required(body.walletAddress, 'walletAddress');
      if (!isAddress(walletAddress)) {
        throw Object.assign(new Error('A valid BNB Smart Chain wallet address is required.'), { statusCode: 400 });
      }
      data = await signedGet(`${TRADING_PATH}/swap`, {
        binanceChainId: CHAIN_ID,
        amount: required(body.amount, 'amount'),
        fromTokenAddress: required(body.fromTokenAddress, 'fromTokenAddress'),
        toTokenAddress: required(body.toTokenAddress, 'toTokenAddress'),
        userWalletAddress: walletAddress,
        quoteId: required(body.quoteId, 'quoteId'),
        slippagePercent: String(body.slippagePercent || '0.5'),
      }, 'any');
    } else if (route === 'approve') {
      const tokenContractAddress = required(body.tokenContractAddress, 'tokenContractAddress');
      if (!isAddress(tokenContractAddress)) {
        throw Object.assign(new Error('A valid token contract address is required.'), { statusCode: 400 });
      }
      const approveAmount = required(body.approveAmount, 'approveAmount');
      if (!/^\d+$/.test(approveAmount) || BigInt(approveAmount) <= 0n) {
        throw Object.assign(
          new Error('Approval amount must be a positive base-unit integer.'),
          { statusCode: 400 },
        );
      }
      data = await signedGet(`${TRADING_PATH}/approve-transaction`, {
        binanceChainId: CHAIN_ID,
        tokenContractAddress,
        approveAmount,
        vendor: body.vendor,
      }, 'any');
    } else if (route === 'simulate') {
      const tx = body.evmTx;
      if (!tx || !isAddress(tx.from) || !isAddress(tx.to)
        || !/^0x[0-9a-fA-F]*$/.test(tx.data || '')) {
        throw Object.assign(new Error('A valid BNB Chain transaction is required for simulation.'), { statusCode: 400 });
      }
      data = await signedRequest('POST', `${TRANSACTION_PATH}/simulate`, {}, {
        binanceChainId: CHAIN_ID,
        evmTx: { from: tx.from, to: tx.to, value: integerString(tx.value || '0', 'Transaction value'), data: tx.data || '0x' },
      });
    } else if (route === 'broadcast') {
      const walletAddress = required(body.walletAddress, 'walletAddress');
      if (!isAddress(walletAddress) || !/^0x[0-9a-fA-F]+$/.test(body.signedTransaction || '')) {
        throw Object.assign(new Error('A valid wallet and signed transaction are required.'), { statusCode: 400 });
      }
      data = await signedRequest('POST', `${TRANSACTION_PATH}/broadcast-transaction`, {}, {
        binanceChainId: CHAIN_ID,
        address: walletAddress,
        signedTransaction: body.signedTransaction,
        enableMevProtection: true,
      });
    } else if (route === 'rfq-submit') {
      data = await signedRequest('POST', `${TRADING_PATH}/order/submit`, {}, {
        requestId: required(body.requestId, 'requestId'),
        userSignature: required(body.userSignature, 'userSignature'),
        vendor: required(body.vendor, 'vendor'),
        quoteId: required(body.quoteId, 'quoteId'),
        ...(body.signingScheme ? { signingScheme: String(body.signingScheme) } : {}),
      });
    } else if (route === 'rfq-status') {
      data = await signedGet(
        `${TRADING_PATH}/order/${encodeURIComponent(required(query.get('orderId'), 'orderId'))}`,
        {},
        'any',
      );
    } else {
      const txHash = required(query.get('txHash'), 'txHash');
      if (!/^0x[a-fA-F0-9]{64}$/.test(txHash)) {
        throw Object.assign(new Error('A valid transaction hash is required.'), { statusCode: 400 });
      }
      data = await signedGet(
        `${TRADING_PATH}/history`,
        { binanceChainId: CHAIN_ID, txHash },
        'any',
      );
    }

    sendJson(response, 200, { source: 'binance', data: route === 'quote' ? data : asData(data) });
  } catch (error) {
    sendJson(response, Number(error?.statusCode) || 502, {
      error: error?.message || 'Binance trading is unavailable.',
    });
  }
  return true;
}

function toMarket(token) {
  const ticker = String(token.underlyingTicker || token.tokenSymbol || '').trim();
  const symbol = String(token.tokenSymbol || '').trim();
  const price = Number(token.tokenPrice);
  const referencePrice = Number(token.referencePrice);
  if (!ticker || !symbol || !Number.isFinite(price) || price <= 0) return null;

  return {
    ticker,
    symbol,
    name: String(token.underlyingName || token.tokenName || ticker),
    provider: token.platformId === 'bstock' ? 'bStock' : 'Ondo',
    contractAddress: String(token.tokenContractAddress || ''),
    decimals: Number(token.tokenDecimals ?? token.decimals ?? 18),
    chainId: CHAIN_ID,
    price,
    referencePrice: Number.isFinite(referencePrice) && referencePrice > 0 ? referencePrice : price,
    referenceChange: Number.isFinite(referencePrice) && referencePrice > 0
      ? ((price - referencePrice) / referencePrice) * 100
      : 0,
    open: Boolean(token.statusInfo?.openState),
    marketStatus: token.statusInfo?.marketStatus || token.statusInfo?.reasonCode || 'Unknown',
    category: 'Tokenized equity',
    badge: ticker.slice(0, 1).toUpperCase(),
  };
}

async function getRwaMarkets() {
  const tokens = await signedGet(RWA_TOKENS_PATH, { binanceChainId: CHAIN_ID });
  const eligibleTokens = tokens.filter((token) =>
    String(token.binanceChainId) === CHAIN_ID && [1, 3].includes(Number(token.assetType))
  );
  const prices = new Map();

  for (let offset = 0; offset < eligibleTokens.length; offset += 100) {
    const batch = eligibleTokens.slice(offset, offset + 100);
    const addresses = batch.map((token) => token.tokenContractAddress).filter(Boolean);
    if (!addresses.length) continue;
    try {
      const rows = await signedGet(RWA_PRICE_PATH, {
        binanceChainId: CHAIN_ID,
        tokenContractAddresses: addresses.join(','),
      });
      rows.forEach((price) => {
        const address = String(price.tokenContractAddress || '').toLowerCase();
        if (address) prices.set(address, price);
      });
    } catch {
      // Token-list prices remain usable if the optional price refresh is unavailable.
    }
  }

  const markets = eligibleTokens.map((token) => {
    const price = prices.get(String(token.tokenContractAddress || '').toLowerCase());
    return toMarket(price ? { ...token, ...price } : token);
  }).filter(Boolean);

  if (!markets.length) throw new Error('Binance returned no usable BNB Chain RWA tokens.');
  return markets;
}

async function getRwaPortfolio(walletAddress) {
  if (!/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
    const error = new Error('A valid BNB Smart Chain wallet address is required.');
    error.statusCode = 400;
    throw error;
  }

  const pnlList = [];
  let cursor = '';
  for (let page = 0; page < 10; page += 1) {
    const data = await signedGet(RWA_PORTFOLIO_PNL_PATH, {
      binanceChainId: CHAIN_ID,
      walletAddress: walletAddress.toLowerCase(),
      cursor,
      limit: 100,
    }, 'object');
    if (!Array.isArray(data.pnlList)) {
      throw new Error('Binance returned an invalid portfolio response.');
    }
    pnlList.push(...data.pnlList);
    cursor = String(data.cursor || '');
    if (!cursor) break;
  }

  if (cursor) {
    throw new Error('Binance portfolio exceeds the maximum of 1000 positions.');
  }
  return pnlList;
}

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'Authorization, Content-Type, Accept',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
  });
  response.end(JSON.stringify(payload));
}

async function handleBinanceRequest(request, response, routedPath) {
  const requestUrl = new URL(routedPath || request.url || '/', 'http://localhost');
  const isMarketsRoute = requestUrl.pathname === '/api/binance/rwa/markets';
  const isPortfolioRoute = requestUrl.pathname === '/api/binance/rwa/portfolio';
  const isTradingRoute = requestUrl.pathname.startsWith('/api/binance/trading/');
  const isAiChatRoute = requestUrl.pathname === '/api/binance/ai/chat';
  if (!isMarketsRoute && !isPortfolioRoute && !isTradingRoute && !isAiChatRoute) return false;
  if ((isTradingRoute || isAiChatRoute) && request.method === 'OPTIONS') {
    response.writeHead(204, {
      'cache-control': 'no-store',
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'Authorization, Content-Type, Accept',
      'access-control-allow-methods': 'GET, POST, OPTIONS',
    });
    response.end();
    return true;
  }
  if (isAiChatRoute) return handleAiChat(request, response);
  if (isTradingRoute) return handleTradingRoute(request, response, requestUrl);
  if (request.method !== 'GET') {
    sendJson(response, 405, { error: 'Method not allowed.' });
    return true;
  }

  try {
    if (isPortfolioRoute) {
      const walletAddress = requestUrl.searchParams.get('walletAddress') || '';
      const positions = await getRwaPortfolio(walletAddress);
      sendJson(response, 200, {
        source: 'binance',
        walletAddress: walletAddress.toLowerCase(),
        positions,
        updatedAt: new Date().toISOString(),
      });
      return true;
    }

    const markets = await getRwaMarkets();
    sendJson(response, 200, { source: 'binance', markets, updatedAt: new Date().toISOString() });
  } catch (error) {
    const statusCode = Number(error?.statusCode) || 502;
    sendJson(response, statusCode, { error: error?.message || 'Binance market data is unavailable.' });
  }
  return true;
}

module.exports = { handleBinanceRequest };
