// Chrome: service worker, применяет настройки прокси через PAC-скрипт.
// Firefox: event page, маршрутизирует каждый запрос через proxy.onRequest.
// Один и тот же файл работает в обоих браузерах (ветвление по IS_FIREFOX).
// State shape (chrome.storage.local):
// {
//   profiles: [{ id, name, scheme: 'socks5'|'socks4'|'http'|'https', host, port, username?, password? }],
//   activeId: string | null,         // null => direct
//   filterMode: 'off'|'whitelist'|'blacklist',
//   whitelist: string[],             // domains/patterns
//   blacklist: string[]
// }

const DEFAULT_STATE = {
  profiles: [],
  activeId: null,
  filterMode: 'off',
  whitelist: [],
  blacklist: []
};

// В Chrome глобала `browser` нет; в Firefox есть browser.proxy.onRequest.
const IS_FIREFOX = typeof browser !== 'undefined' &&
  !!(browser.proxy && browser.proxy.onRequest);

async function getState() {
  const data = await chrome.storage.local.get(DEFAULT_STATE);
  return { ...DEFAULT_STATE, ...data };
}

// Кэш состояния для Firefox: onRequest вызывается на каждый запрос,
// ходить в storage каждый раз незачем. Сбрасывается в storage.onChanged.
let stateCache = null;
async function getCachedState() {
  if (!stateCache) stateCache = await getState();
  return stateCache;
}

function escapeForPac(str) {
  return String(str).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// Chrome требует, чтобы pacScript.data был чистым ASCII, иначе settings.set()
// падает с "supports only ASCII code (encode URLs in Punycode format)".
// Любой не-ASCII символ в строковых литералах заменяем на \uXXXX.
function escapeNonAscii(str) {
  return String(str).replace(/[^\x00-\x7F]/g, (ch) => {
    return '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0');
  });
}

// Chrome передает в FindProxyForURL хост в punycode, поэтому IDN-домены
// в списках тоже приводим к punycode - иначе "мойсайт.рф" никогда не совпадет.
// Конвертируем по меткам: метку с "*" не трогаем (punycode внутри метки с
// джокером бессмыслен - IDNA закодировал бы и сам "*").
function punycodeLabel(label) {
  if (!label || !/[^\x00-\x7F]/.test(label) || label.indexOf('*') !== -1) return label;
  try {
    const host = new URL('http://' + label + '.test/').hostname;
    const dot = host.lastIndexOf('.test');
    return dot > 0 ? host.slice(0, dot) : label;
  } catch (e) {
    return label;
  }
}

function toPunycode(pattern) {
  const s = String(pattern).toLowerCase().trim();
  if (!s || !/[^\x00-\x7F]/.test(s)) return s;
  return s.split('.').map(punycodeLabel).join('.');
}

function normalizeList(list) {
  return (list || []).map(toPunycode).filter(Boolean);
}

function pacProxyToken(profile) {
  // Хост прокси тоже может быть IDN - в PAC нужен punycode
  const host = toPunycode(profile.host);
  switch (profile.scheme) {
    case 'socks5':
      // Только SOCKS5: у него DNS резолвится на стороне прокси.
      // Fallback на "SOCKS" (SOCKS4) убран - SOCKS4 требует локального
      // резолва имени, что дает DNS-утечку реальной страны.
      return `SOCKS5 ${host}:${profile.port}`;
    case 'socks4':
      return `SOCKS ${host}:${profile.port}`;
    case 'https':
      return `HTTPS ${host}:${profile.port}`;
    case 'http':
    default:
      return `PROXY ${host}:${profile.port}`;
  }
}

function buildPacScript(profile, filterMode, whitelist, blacklist) {
  const proxyToken = pacProxyToken(profile);
  const wl = JSON.stringify(normalizeList(whitelist));
  const bl = JSON.stringify(normalizeList(blacklist));
  const mode = JSON.stringify(filterMode || 'off');

  const script = `
    var PROXY = "${escapeForPac(proxyToken)}";
    var MODE = ${mode};
    var WL = ${wl};
    var BL = ${bl};

    function matchesPattern(host, pattern) {
      if (!pattern) return false;
      host = host.toLowerCase();
      pattern = pattern.toLowerCase();
      // Wildcard support: *.example.com or *example*
      if (pattern.indexOf('*') !== -1) {
        var re = new RegExp('^' + pattern.replace(/[.+^\${}()|[\\]\\\\]/g, '\\\\$&').replace(/\\*/g, '.*') + '$');
        return re.test(host);
      }
      // Exact or suffix match (treats pattern as domain)
      if (host === pattern) return true;
      if (host.length > pattern.length && host.slice(-pattern.length - 1) === '.' + pattern) return true;
      return false;
    }

    function listMatches(host, list) {
      for (var i = 0; i < list.length; i++) {
        if (matchesPattern(host, list[i])) return true;
      }
      return false;
    }

    function isIpV4Literal(host) {
      var parts = host.split('.');
      if (parts.length !== 4) return false;
      for (var i = 0; i < 4; i++) {
        var p = parts[i];
        if (p.length === 0 || p.length > 3) return false;
        for (var j = 0; j < p.length; j++) {
          var c = p.charCodeAt(j);
          if (c < 48 || c > 57) return false;
        }
        if (parseInt(p, 10) > 255) return false;
      }
      return true;
    }

    function isPrivateHost(host) {
      var h = host.toLowerCase();
      if (h.indexOf(':') !== -1) {
        // IPv6-литералы: loopback, link-local, ULA
        if (h === '::1' || h === '[::1]') return true;
        if (h.indexOf('fe80') === 0 || h.indexOf('[fe80') === 0) return true;
        if (h.indexOf('fc') === 0 || h.indexOf('fd') === 0) return true;
        if (h.indexOf('[fc') === 0 || h.indexOf('[fd') === 0) return true;
        return false;
      }
      if (!isIpV4Literal(h)) return false;
      // isInNet на литерале IP не порождает DNS-запрос
      return isInNet(h, "10.0.0.0", "255.0.0.0") ||
             isInNet(h, "172.16.0.0", "255.240.0.0") ||
             isInNet(h, "192.168.0.0", "255.255.0.0") ||
             isInNet(h, "127.0.0.0", "255.0.0.0") ||
             isInNet(h, "169.254.0.0", "255.255.0.0");
    }

    function FindProxyForURL(url, host) {
      // dnsResolve() здесь не используется намеренно.
      // Он резолвит имя ЛОКАЛЬНЫМ DNS до выбора прокси, из-за чего
      // авторитативный сервер сайта видит российский резолвер (DNS leak),
      // даже если сам трафик идет через прокси.
      // Все проверки - только по имени хоста и по литералам IP.
      if (isPlainHostName(host) ||
          host === "localhost" ||
          shExpMatch(host, "*.local") ||
          shExpMatch(host, "*.localdomain") ||
          shExpMatch(host, "*.lan") ||
          shExpMatch(host, "*.home.arpa") ||
          shExpMatch(host, "*.in-addr.arpa") ||
          isPrivateHost(host)) {
        return "DIRECT";
      }

      if (MODE === "whitelist") {
        return listMatches(host, WL) ? PROXY : "DIRECT";
      }
      if (MODE === "blacklist") {
        return listMatches(host, BL) ? "DIRECT" : PROXY;
      }
      return PROXY;
    }
  `;

  // Комментарии на русском тоже не-ASCII, поэтому экранируем весь скрипт целиком.
  return escapeNonAscii(script);
}

// ---------------------------------------------------------------------------
// Firefox: та же логика фильтрации, что и в PAC-скрипте, но обычным JS.
// ---------------------------------------------------------------------------

function hostMatchesPattern(host, pattern) {
  if (!pattern) return false;
  host = host.toLowerCase();
  pattern = pattern.toLowerCase();
  if (pattern.indexOf('*') !== -1) {
    const re = new RegExp(
      '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$'
    );
    return re.test(host);
  }
  if (host === pattern) return true;
  return host.length > pattern.length && host.slice(-pattern.length - 1) === '.' + pattern;
}

function hostInList(host, list) {
  for (const pattern of list) {
    if (hostMatchesPattern(host, pattern)) return true;
  }
  return false;
}

function isPrivateIpv4(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  const o = m.slice(1).map(Number);
  if (o.some(n => n > 255)) return false;
  return o[0] === 10 ||
    o[0] === 127 ||
    (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
    (o[0] === 192 && o[1] === 168) ||
    (o[0] === 169 && o[1] === 254);
}

// Локальные и приватные адреса всегда идут напрямую (как и в PAC-варианте).
function isLocalHost(rawHost) {
  const h = rawHost.toLowerCase().replace(/^\[|\]$/g, '');
  if (h.indexOf(':') !== -1) {
    return h === '::1' || /^fe80/.test(h) || /^f[cd]/.test(h);
  }
  return h.indexOf('.') === -1 ||
    h === 'localhost' ||
    /\.(local|localdomain|lan)$/.test(h) ||
    /\.(home\.arpa|in-addr\.arpa)$/.test(h) ||
    isPrivateIpv4(h);
}

function shouldUseProxy(host, state) {
  if (isLocalHost(host)) return false;
  if (state.filterMode === 'whitelist') {
    return hostInList(host, normalizeList(state.whitelist));
  }
  if (state.filterMode === 'blacklist') {
    return !hostInList(host, normalizeList(state.blacklist));
  }
  return true;
}

function firefoxProxyInfo(profile) {
  const info = {
    host: toPunycode(profile.host),
    port: Number(profile.port)
  };
  switch (profile.scheme) {
    case 'socks5':
      info.type = 'socks';
      info.proxyDNS = true; // DNS резолвится на стороне прокси - без утечки
      break;
    case 'socks4':
      info.type = 'socks4';
      break;
    case 'https':
      info.type = 'https';
      break;
    case 'http':
    default:
      info.type = 'http';
  }
  // Для SOCKS5 логин/пароль передаются прямо в ProxyInfo;
  // для http(s) - через onAuthRequired (см. ниже).
  if (info.type === 'socks' && profile.username) {
    info.username = profile.username;
    info.password = profile.password || '';
  }
  return info;
}

const ICONS = {
  on: {
    16: 'icons/on16.png',
    32: 'icons/on32.png',
    48: 'icons/on48.png',
    128: 'icons/on128.png'
  },
  off: {
    16: 'icons/off16.png',
    32: 'icons/off32.png',
    48: 'icons/off48.png',
    128: 'icons/off128.png'
  }
};

async function setIcon(which) {
  try {
    await chrome.action.setIcon({ path: ICONS[which] });
  } catch (e) {
    // ignore (e.g. service worker race on startup)
  }
}

// Firefox: сами настройки прокси не меняются - маршрутизацию делает
// слушатель proxy.onRequest. Здесь обновляем только иконку и подсказку.
async function applyProxyFirefox() {
  stateCache = null;
  const state = await getCachedState();
  const profile = state.profiles.find(p => p.id === state.activeId);

  await chrome.storage.local.remove('lastError');
  await chrome.action.setBadgeText({ text: '' });
  if (!profile) {
    await chrome.action.setTitle({ title: 'Web Liberty - direct' });
    await setIcon('off');
    return;
  }
  await chrome.action.setTitle({
    title: `Web Liberty - ${profile.name || 'proxy'} (${profile.scheme} ${profile.host}:${profile.port})`
  });
  await setIcon('on');
}

async function applyProxy() {
  if (IS_FIREFOX) return applyProxyFirefox();

  const state = await getState();
  const profile = state.profiles.find(p => p.id === state.activeId);

  if (!profile) {
    await chrome.proxy.settings.set({
      value: { mode: 'direct' },
      scope: 'regular'
    });
    await chrome.action.setBadgeText({ text: '' });
    await chrome.action.setTitle({ title: 'Web Liberty - direct' });
    await setIcon('off');
    await chrome.storage.local.remove('lastError');
    return;
  }

  const pac = buildPacScript(profile, state.filterMode, state.whitelist, state.blacklist);
  try {
    await chrome.proxy.settings.set({
      value: {
        mode: 'pac_script',
        pacScript: { data: pac, mandatory: false }
      },
      scope: 'regular'
    });
  } catch (e) {
    // Прокси-настройками может владеть другое расширение с более высоким
    // приоритетом - тогда set() бросает и раньше иконка молча оставалась off.
    await chrome.storage.local.set({ lastError: String(e && e.message || e) });
    await chrome.action.setBadgeText({ text: '!' });
    await chrome.action.setBadgeBackgroundColor({ color: '#c0392b' });
    await chrome.action.setTitle({ title: 'Web Liberty - ошибка: ' + (e && e.message || e) });
    await setIcon('off');
    return;
  }

  // Проверяем, что настройки реально за нами, а не за другим расширением
  let levelOfControl = '';
  try {
    const got = await chrome.proxy.settings.get({ incognito: false });
    levelOfControl = got.levelOfControl || '';
  } catch (e) {
    levelOfControl = '';
  }

  if (levelOfControl && levelOfControl !== 'controlled_by_this_extension') {
    await chrome.storage.local.set({ lastError: 'levelOfControl: ' + levelOfControl });
    await chrome.action.setBadgeText({ text: '!' });
    await chrome.action.setBadgeBackgroundColor({ color: '#c0392b' });
    await chrome.action.setTitle({ title: 'Web Liberty - настройками прокси владеет другое расширение (' + levelOfControl + ')' });
    await setIcon('off');
    return;
  }

  await chrome.storage.local.remove('lastError');
  await chrome.action.setBadgeText({ text: '' });
  await chrome.action.setTitle({
    title: `Web Liberty - ${profile.name || 'proxy'} (${profile.scheme} ${profile.host}:${profile.port})`
  });
  await setIcon('on');
}

if (IS_FIREFOX) {
  // Маршрутизация: на каждый запрос решаем, идти ли через прокси.
  browser.proxy.onRequest.addListener(
    async (details) => {
      const state = await getCachedState();
      const profile = state.profiles.find(p => p.id === state.activeId);
      if (!profile || !profile.host || !profile.port) return { type: 'direct' };

      let host;
      try {
        host = new URL(details.url).hostname;
      } catch (e) {
        return { type: 'direct' };
      }
      if (!shouldUseProxy(host, state)) return { type: 'direct' };
      return firefoxProxyInfo(profile);
    },
    { urls: ['<all_urls>'] }
  );

  // Логин/пароль для HTTP(S)-прокси. Firefox повторно вызывает слушатель,
  // если учётные данные неверны, поэтому на повторный запрос с тем же
  // requestId отвечаем пустым результатом, иначе получится бесконечный цикл.
  const authAttempted = new Set();
  browser.webRequest.onAuthRequired.addListener(
    async (details) => {
      if (!details.isProxy) return {};
      if (authAttempted.has(details.requestId)) return {};
      authAttempted.add(details.requestId);
      if (authAttempted.size > 500) authAttempted.clear();

      const state = await getCachedState();
      const profile = state.profiles.find(p => p.id === state.activeId);
      if (profile && profile.username) {
        return {
          authCredentials: {
            username: profile.username,
            password: profile.password || ''
          }
        };
      }
      return {};
    },
    { urls: ['<all_urls>'] },
    ['blocking']
  );
} else {
  // Chrome: provide credentials for HTTP(S) proxies that require auth
  chrome.webRequest.onAuthRequired.addListener(
    async (details, callback) => {
      if (!details.isProxy) {
        callback({});
        return;
      }
      const state = await getState();
      const profile = state.profiles.find(p => p.id === state.activeId);
      if (profile && profile.username) {
        callback({
          authCredentials: {
            username: profile.username,
            password: profile.password || ''
          }
        });
      } else {
        callback({});
      }
    },
    { urls: ['<all_urls>'] },
    ['asyncBlocking']
  );
}

chrome.runtime.onInstalled.addListener(applyProxy);
chrome.runtime.onStartup.addListener(applyProxy);

// Применяем настройки при каждом старте service worker'а.
// MV3-воркер выгружается и просыпается заново, а onInstalled/onStartup при
// перезагрузке распакованного расширения могут не сработать - тогда прокси
// не применялся и иконка молча оставалась серой.
applyProxy();

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  stateCache = null;
  const keys = ['profiles', 'activeId', 'filterMode', 'whitelist', 'blacklist'];
  if (keys.some(k => k in changes)) applyProxy();
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === 'APPLY_PROXY') {
    applyProxy().then(() => sendResponse({ ok: true }));
    return true;
  }
});
