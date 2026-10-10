const DEFAULTS = {
  profiles: [],
  activeId: null,
  filterMode: 'off',
  whitelist: [],
  blacklist: []
};

let state = { ...DEFAULTS };

function uid() {
  return 'p_' + Math.random().toString(36).slice(2, 10);
}

async function load() {
  state = { ...DEFAULTS, ...(await chrome.storage.local.get(DEFAULTS)) };
  renderProfiles();
  renderFilter();
}

function renderProfiles() {
  const tbody = document.getElementById('profileBody');
  const empty = document.getElementById('emptyProfiles');
  tbody.innerHTML = '';
  empty.classList.toggle('hidden', state.profiles.length > 0);

  const tpl = document.getElementById('rowTpl');
  for (const p of state.profiles) {
    const row = tpl.content.firstElementChild.cloneNode(true);
    row.dataset.id = p.id;
    const $ = (sel) => row.querySelector(sel);
    $('.name').value = p.name || '';
    $('.scheme').value = p.scheme || 'socks5';
    $('.host').value = p.host || '';
    $('.port').value = p.port || '';
    $('.username').value = p.username || '';
    $('.password').value = p.password || '';
    updateActiveBtn(row, p.id === state.activeId, p.scheme || 'socks5');
    tbody.appendChild(row);
  }
}

function renderFilter() {
  document.querySelectorAll('input[name="filterMode"]').forEach(r => {
    r.checked = r.value === state.filterMode;
  });
  document.getElementById('whitelist').value = (state.whitelist || []).join('\n');
  document.getElementById('blacklist').value = (state.blacklist || []).join('\n');
}

function updateActiveBtn(row, isActive, scheme) {
  const btn = row.querySelector('.active-btn');
  if (!btn) return;
  btn.dataset.scheme = scheme || 'socks5';
  btn.classList.toggle('is-active', !!isActive);
  btn.textContent = isActive ? 'Active' : 'Activate';
}

function collectProfiles() {
  const rows = document.querySelectorAll('#profileBody tr');
  const profiles = [];
  let activeId = state.activeId;
  const validIds = new Set();
  for (const row of rows) {
    const id = row.dataset.id;
    const $ = (sel) => row.querySelector(sel);
    const profile = {
      id,
      name: $('.name').value.trim() || 'Proxy',
      scheme: $('.scheme').value,
      host: $('.host').value.trim(),
      port: parseInt($('.port').value, 10) || 0,
      username: $('.username').value,
      password: $('.password').value
    };
    // Reflect scheme on active button regardless of validity
    updateActiveBtn(row, id === activeId, profile.scheme);
    if (!profile.host || !profile.port) continue;
    profiles.push(profile);
    validIds.add(id);
  }
  if (activeId && !validIds.has(activeId)) activeId = null;
  return { profiles, activeId };
}

async function persistProfiles() {
  const { profiles, activeId } = collectProfiles();
  state.profiles = profiles;
  state.activeId = profiles.find(p => p.id === activeId) ? activeId : (state.activeId && profiles.find(p => p.id === state.activeId) ? state.activeId : null);
  await chrome.storage.local.set({ profiles: state.profiles, activeId: state.activeId });
}

document.getElementById('addProfile').addEventListener('click', async () => {
  state.profiles.push({
    id: uid(),
    name: 'New proxy',
    scheme: 'socks5',
    host: '',
    port: 1080,
    username: '',
    password: ''
  });
  renderProfiles();
});

document.getElementById('profileBody').addEventListener('click', async (e) => {
  const tr = e.target.closest('tr');
  if (!tr) return;
  if (e.target.classList.contains('del')) {
    const id = tr.dataset.id;
    state.profiles = state.profiles.filter(p => p.id !== id);
    if (state.activeId === id) state.activeId = null;
    await chrome.storage.local.set({ profiles: state.profiles, activeId: state.activeId });
    renderProfiles();
    return;
  }
  if (e.target.classList.contains('active-btn')) {
    e.preventDefault();
    // Persist any pending edits in this row first
    await persistProfiles();
    const id = tr.dataset.id;
    const profile = state.profiles.find(p => p.id === id);
    if (!profile) {
      flash('Fill in host and port first', true);
      return;
    }
    state.activeId = (state.activeId === id) ? null : id;
    await chrome.storage.local.set({ activeId: state.activeId });
    renderProfiles();
  }
});

// Auto-save on field changes
document.getElementById('profileBody').addEventListener('change', async () => {
  await persistProfiles();
});
document.getElementById('profileBody').addEventListener('input', debounce(async () => {
  await persistProfiles();
}, 400));

document.querySelectorAll('input[name="filterMode"]').forEach(r => {
  r.addEventListener('change', async () => {
    state.filterMode = r.value;
    await chrome.storage.local.set({ filterMode: state.filterMode });
  });
});

document.getElementById('saveLists').addEventListener('click', async () => {
  const wl = document.getElementById('whitelist').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const bl = document.getElementById('blacklist').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  state.whitelist = wl;
  state.blacklist = bl;
  await chrome.storage.local.set({ whitelist: wl, blacklist: bl });
  flash('Saved');
});

document.getElementById('exportBtn').addEventListener('click', async () => {
  const data = await chrome.storage.local.get(DEFAULTS);
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'proxy-switcher-config.json';
  a.click();
  URL.revokeObjectURL(url);
});

document.getElementById('importBtn').addEventListener('click', () => {
  document.getElementById('importFile').click();
});
document.getElementById('importFile').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    const sanitized = {
      profiles: Array.isArray(data.profiles) ? data.profiles : [],
      activeId: data.activeId || null,
      filterMode: ['off', 'whitelist', 'blacklist'].includes(data.filterMode) ? data.filterMode : 'off',
      whitelist: Array.isArray(data.whitelist) ? data.whitelist : [],
      blacklist: Array.isArray(data.blacklist) ? data.blacklist : []
    };
    await chrome.storage.local.set(sanitized);
    await load();
    flash('Imported');
  } catch (err) {
    flash('Import failed: ' + err.message, true);
  }
});

function flash(msg, isErr = false) {
  const el = document.getElementById('saveStatus');
  el.textContent = msg;
  el.className = 'status ' + (isErr ? 'err' : 'ok');
  setTimeout(() => { el.textContent = ''; }, 1500);
}

function debounce(fn, ms) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function handleHash() {
  const hash = (location.hash || '').replace('#', '');
  if (!hash) return;
  if (hash === 'add') {
    document.getElementById('addProfile').click();
    const lastRow = document.querySelector('#profileBody tr:last-child .name');
    if (lastRow) {
      lastRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
      lastRow.focus();
    }
  } else if (hash === 'whitelist' || hash === 'blacklist') {
    const ta = document.getElementById(hash);
    if (ta) {
      ta.scrollIntoView({ behavior: 'smooth', block: 'center' });
      ta.focus();
      const col = ta.closest('.list-col');
      if (col) {
        col.classList.add('flash-highlight');
        setTimeout(() => col.classList.remove('flash-highlight'), 1500);
      }
    }
  }
}

load().then(handleHash);
