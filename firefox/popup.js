const DEFAULTS = {
  profiles: [],
  activeId: null,
  filterMode: 'off',
  whitelist: [],
  blacklist: []
};

async function load() {
  const state = { ...DEFAULTS, ...(await chrome.storage.local.get(DEFAULTS)) };
  renderProfiles(state);
  renderFilter(state);
  await renderError();
}

// Показываем причину, если прокси не применился (иначе иконка просто серая
// и непонятно, что сломалось).
async function renderError() {
  const banner = document.getElementById('errBanner');
  if (!banner) return;
  const { lastError } = await chrome.storage.local.get({ lastError: null });
  if (lastError) {
    banner.textContent = 'Прокси не применен: ' + lastError;
    banner.classList.remove('hidden');
  } else {
    banner.textContent = '';
    banner.classList.add('hidden');
  }
}

function renderProfiles(state) {
  const list = document.getElementById('profileList');
  list.innerHTML = '';
  document.getElementById('directRadio').checked = !state.activeId;

  for (const p of state.profiles) {
    const row = document.createElement('label');
    row.className = 'row';
    // Собираем через DOM, а не innerHTML: id может прийти из импортированного JSON.
    const radio = document.createElement('input');
    radio.type = 'radio';
    radio.name = 'active';
    radio.value = String(p.id);
    radio.checked = p.id === state.activeId;

    const label = document.createElement('span');
    label.className = 'label';
    const strong = document.createElement('strong');
    strong.textContent = p.name;
    label.appendChild(strong);

    const meta = document.createElement('span');
    meta.className = 'meta';
    meta.textContent = `${p.scheme}://${p.host}:${p.port}`;

    row.append(radio, label, meta);
    list.appendChild(row);
  }
}

function renderFilter(state) {
  document.querySelectorAll('input[name="filterMode"]').forEach(r => {
    r.checked = r.value === state.filterMode;
  });
}

document.addEventListener('change', async (e) => {
  if (e.target.name === 'active') {
    const value = e.target.value || null;
    await chrome.storage.local.set({ activeId: value });
    flash('Applied');
    setTimeout(renderError, 300);
  } else if (e.target.name === 'filterMode') {
    await chrome.storage.local.set({ filterMode: e.target.value });
    flash('Filter updated');
    setTimeout(renderError, 300);
  }
});

function openOptions(hash) {
  const url = chrome.runtime.getURL('options.html') + (hash ? hash : '');
  chrome.tabs.create({ url });
}

document.getElementById('openOptions').addEventListener('click', () => openOptions());
document.getElementById('addProxy').addEventListener('click', () => openOptions('#add'));

document.querySelectorAll('.mini-btn[data-edit]').forEach(btn => {
  btn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    openOptions('#' + btn.dataset.edit);
  });
});

function flash(msg) {
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = 'status ok';
  setTimeout(() => { el.textContent = ''; }, 1200);
}

load();
