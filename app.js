const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const API_BASE = '/api';
const STORAGE = {
  token: 'bhm_token',
  theme: 'bhm_theme'
};

const DEFAULT_HOLDINGS = [
  { symbol: 'BTC', name: 'Bitcoin', pct: 42, color: '#46a0ff', price: 104821, change: 2.1 },
  { symbol: 'ETH', name: 'Ethereum', pct: 28, color: '#7c4dff', price: 5148, change: 1.4 },
  { symbol: 'SOL', name: 'Solana', pct: 16, color: '#36d399', price: 311, change: -0.5 },
  { symbol: 'USDC', name: 'USDC', pct: 14, color: '#ffd36f', price: 1, change: 0 }
];

const appState = {
  user: null,
  portfolio: {
    totalBalance: 128440.92,
    availableCash: 19200,
    holdings: [...DEFAULT_HOLDINGS],
    wallet: null,
    kycSubmitted: false,
    kycStep: 0,
    kycStatus: 'draft',
    kycReviewerNote: null
  },
  activity: [],
  transactions: [],
  settings: null,
  addresses: [],
  kycFiles: [],
  admin: {
    stats: null,
    users: [],
    pendingFiles: []
  }
};

function getToken() {
  return localStorage.getItem(STORAGE.token);
}

function setToken(token) {
  localStorage.setItem(STORAGE.token, token);
}

function clearToken() {
  localStorage.removeItem(STORAGE.token);
}

async function api(path, options = {}) {
  const { method = 'GET', body, auth = true } = options;
  const headers = {};
  const requestOptions = { method, headers };

  if (auth && getToken()) headers.Authorization = `Bearer ${getToken()}`;
  if (body instanceof FormData) {
    requestOptions.body = body;
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    requestOptions.body = JSON.stringify(body);
  }

  const response = await fetch(`${API_BASE}${path}`, requestOptions);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function currency(value) {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: value > 1000 ? 0 : 2
  }).format(value);
}

function createToastContainer() {
  let stack = $('.toast-stack');
  if (!stack) {
    stack = document.createElement('div');
    stack.className = 'toast-stack';
    document.body.appendChild(stack);
  }
  return stack;
}

function showToast(message, type = 'info') {
  const stack = createToastContainer();
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  stack.appendChild(toast);
  setTimeout(() => toast.remove(), 2800);
}

function initTheme() {
  const saved = localStorage.getItem(STORAGE.theme) || 'dark';
  document.body.classList.toggle('light-theme', saved === 'light');
  $$('.theme-toggle').forEach(btn => btn.textContent = saved === 'light' ? 'Dark mode' : 'Light mode');
}

function toggleTheme() {
  const isLight = document.body.classList.toggle('light-theme');
  localStorage.setItem(STORAGE.theme, isLight ? 'light' : 'dark');
  $$('.theme-toggle').forEach(btn => btn.textContent = isLight ? 'Dark mode' : 'Light mode');
}

function setupThemeToggles() {
  $$('.theme-toggle').forEach(btn => btn.addEventListener('click', toggleTheme));
}

function toggleChat() {
  const launcher = $('#chatLauncher');
  const panel = $('#chatPanel');
  const close = $('[data-close-chat]');
  if (!launcher || !panel) return;
  launcher.addEventListener('click', () => panel.classList.toggle('hidden'));
  close?.addEventListener('click', () => panel.classList.add('hidden'));
}

function setupPasswordToggles() {
  $$('[data-toggle-password]').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = document.getElementById(btn.dataset.togglePassword);
      if (!input) return;
      input.type = input.type === 'password' ? 'text' : 'password';
      btn.textContent = input.type === 'password' ? 'Show' : 'Hide';
    });
  });
}

async function requireAuthIfNeeded() {
  const protectedPage = document.body.dataset.protected === 'true';
  if (!getToken()) {
    if (protectedPage) window.location.href = 'login.html';
    return false;
  }

  try {
    const data = await api('/auth/me');
    appState.user = data.user;
    if (document.body.dataset.adminRequired === 'true' && appState.user.role !== 'admin') {
      showToast('Admin access required', 'error');
      setTimeout(() => { window.location.href = 'dashboard.html'; }, 300);
      return false;
    }
    return true;
  } catch (error) {
    clearToken();
    if (protectedPage) window.location.href = 'login.html';
    return false;
  }
}

async function logout() {
  try {
    if (getToken()) await api('/auth/logout', { method: 'POST' });
  } catch (_) {
    // ignore logout errors
  }
  clearToken();
  showToast('Signed out', 'info');
  setTimeout(() => { window.location.href = 'login.html'; }, 300);
}

function bindLogoutButtons() {
  $$('[data-logout]').forEach(btn => btn.addEventListener('click', logout));
}

function syncAdminVisibility() {
  const isAdmin = appState.user?.role === 'admin';
  $$('.admin-only').forEach(el => el.classList.toggle('hidden', !isAdmin));
}

function updateUserUI() {
  if (!appState.user) return;
  $$('[data-user-firstname]').forEach(el => el.textContent = appState.user.firstName || 'Trader');
  $$('[data-user-fullname]').forEach(el => el.textContent = `${appState.user.firstName || 'Alex'} ${appState.user.lastName || 'Morgan'}`);
  $$('[data-user-email]').forEach(el => el.textContent = appState.user.email || 'demo@blockharbor.app');
  $$('.avatar').forEach(el => {
    const first = (appState.user.firstName || 'A')[0];
    const last = (appState.user.lastName || 'M')[0];
    el.textContent = `${first}${last}`.toUpperCase();
  });
  syncAdminVisibility();
}

function setupAuthForms() {
  $('#signupForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      firstName: $('#firstName')?.value?.trim(),
      lastName: $('#lastName')?.value?.trim(),
      email: $('#signupEmail')?.value?.trim(),
      password: $('#signupPassword')?.value || '',
      country: $('#country')?.value || '',
      phone: $('#phoneNumber')?.value?.trim() || ''
    };

    try {
      const data = await api('/auth/signup', { method: 'POST', body: payload, auth: false });
      setToken(data.token);
      appState.user = data.user;
      showToast('Account created successfully', 'success');
      setTimeout(() => { window.location.href = 'kyc.html'; }, 350);
    } catch (error) {
      showToast(error.message, 'error');
    }
  });

  $('#loginForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      email: $('#loginEmail')?.value?.trim(),
      password: $('#loginPassword')?.value || ''
    };

    try {
      const data = await api('/auth/login', { method: 'POST', body: payload, auth: false });
      setToken(data.token);
      appState.user = data.user;
      showToast('Welcome back', 'success');
      setTimeout(() => { window.location.href = data.user.role === 'admin' ? 'admin.html' : 'dashboard.html'; }, 300);
    } catch (error) {
      showToast(error.message, 'error');
    }
  });

  $('#newsletterForm')?.addEventListener('submit', (e) => {
    e.preventDefault();
    showToast('Newsletter signup captured in UI demo', 'success');
    e.target.reset();
  });

  $('#forgotPasswordBtn')?.addEventListener('click', () => $('#forgotPasswordModal')?.classList.add('open'));
  $$('[data-close-modal]').forEach(btn => btn.addEventListener('click', () => btn.closest('.modal-overlay')?.classList.remove('open')));
  $('#forgotForm')?.addEventListener('submit', (e) => {
    e.preventDefault();
    showToast('Password reset flow is a UI placeholder', 'info');
    $('#forgotPasswordModal')?.classList.remove('open');
  });
}

function setupStrengthMeter() {
  const input = $('#signupPassword');
  const fill = $('#strengthFill');
  const label = $('#strengthLabel');
  if (!input || !fill || !label) return;

  const update = () => {
    const value = input.value;
    let score = 0;
    if (value.length >= 8) score += 1;
    if (/[A-Z]/.test(value)) score += 1;
    if (/\d/.test(value)) score += 1;
    if (/[^A-Za-z0-9]/.test(value)) score += 1;
    const map = [
      { width: '12%', text: 'Too weak', bg: 'linear-gradient(135deg, #ff6f91, #ffa36c)' },
      { width: '32%', text: 'Weak', bg: 'linear-gradient(135deg, #ff6f91, #ffd36f)' },
      { width: '58%', text: 'Fair', bg: 'linear-gradient(135deg, #ffd36f, #7dd3fc)' },
      { width: '82%', text: 'Strong', bg: 'linear-gradient(135deg, #7dd3fc, #46a0ff)' },
      { width: '100%', text: 'Very strong', bg: 'linear-gradient(135deg, #36d399, #46a0ff)' }
    ][score];
    fill.style.width = map.width;
    fill.style.background = map.bg;
    label.textContent = map.text;
  };

  input.addEventListener('input', update);
  update();
}

async function connectWallet(statusEl) {
  if (!statusEl) return;
  if (!window.ethereum) {
    statusEl.textContent = 'No browser wallet detected. Install MetaMask to enable real connection.';
    showToast('MetaMask not detected', 'error');
    return;
  }

  try {
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    const wallet = accounts?.[0];
    if (!wallet) {
      statusEl.textContent = 'Wallet connection cancelled';
      return;
    }
    await api('/profile/wallet', { method: 'POST', body: { address: wallet } });
    appState.portfolio.wallet = wallet;
    renderWalletState();
    showToast('Wallet connected successfully', 'success');
  } catch (error) {
    statusEl.textContent = 'Wallet connection request was rejected.';
    showToast(error.message || 'Wallet connection failed', 'error');
  }
}

function renderWalletState() {
  const wallet = appState.portfolio.wallet;
  const statusText = wallet ? `Connected: ${wallet.slice(0, 6)}...${wallet.slice(-4)}` : 'Wallet not connected';
  $('#walletStatus') && ($('#walletStatus').textContent = statusText);
  $('#walletBadge') && ($('#walletBadge').textContent = wallet ? 'Connected' : 'Not connected');
}

function setupWalletButtons() {
  const statusEl = $('#walletStatus');
  ['#walletConnectBtn', '#walletConnectBtnSecondary', '#walletConnectBtnTertiary'].forEach(id => {
    $(id)?.addEventListener('click', () => connectWallet(statusEl));
  });
}

function renderHoldings() {
  const tbody = $('#holdingsTableBody');
  if (!tbody) return;
  tbody.innerHTML = appState.portfolio.holdings.map(item => `
    <tr>
      <td>${item.name}</td>
      <td>${item.pct}%</td>
      <td>${currency(item.price)}</td>
      <td class="${item.change >= 0 ? 'up' : 'down'}">${item.change >= 0 ? '+' : ''}${item.change}%</td>
    </tr>
  `).join('');
}

function renderActivity() {
  const list = $('#activityList');
  if (!list) return;
  list.innerHTML = appState.activity.map(item => `<li><span>${item.label}</span><em>${item.time}</em></li>`).join('');
}

function renderTransactionsPage() {
  const body = $('#transactionsTableBody');
  if (!body) return;
  body.innerHTML = appState.transactions.map(item => `
    <tr>
      <td>${item.type}</td>
      <td>${item.asset}</td>
      <td>${item.amount}</td>
      <td>${item.value}</td>
      <td>${item.status}</td>
      <td>${item.when}</td>
    </tr>
  `).join('');
  $('#txCount') && ($('#txCount').textContent = `${appState.transactions.length} items`);
}

function renderAllocationChart() {
  const mount = $('#allocationChart');
  if (!mount) return;
  const holdings = appState.portfolio.holdings;
  const radius = 76;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const segments = holdings.map(item => {
    const length = circumference * (item.pct / 100);
    const segment = `<circle cx="100" cy="100" r="${radius}" fill="none" stroke="${item.color}" stroke-width="18" stroke-linecap="round" stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="-${offset}" transform="rotate(-90 100 100)"></circle>`;
    offset += length;
    return segment;
  }).join('');

  mount.innerHTML = `
    <svg viewBox="0 0 200 200" class="chart-ring" aria-hidden="true">
      <circle cx="100" cy="100" r="${radius}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="18"></circle>
      ${segments}
      <text x="100" y="95" fill="currentColor" text-anchor="middle" font-size="14">Allocation</text>
      <text x="100" y="120" fill="currentColor" text-anchor="middle" font-size="26" font-weight="700">100%</text>
    </svg>
    <div class="legend">
      ${holdings.map(item => `<div class="legend-item"><span><i class="dot" style="background:${item.color}"></i>${item.name}</span><b>${item.pct}%</b></div>`).join('')}
    </div>
  `;
}

function renderDashboard() {
  $('#totalBalance') && ($('#totalBalance').textContent = currency(appState.portfolio.totalBalance));
  $('#availableCash') && ($('#availableCash').textContent = currency(appState.portfolio.availableCash));
  $('#kycStatus') && ($('#kycStatus').textContent = appState.portfolio.kycStatus || (appState.portfolio.kycSubmitted ? 'submitted' : 'in review'));
  $('#kycDetail') && ($('#kycDetail').textContent = appState.portfolio.kycSubmitted ? 'Final package awaiting review' : `${Math.max(1, appState.portfolio.kycStep + 1)} of 5 steps complete`);
  $('#portfolioInline') && ($('#portfolioInline').textContent = `${appState.portfolio.holdings.length} tracked assets`);
  const reviewerPanel = $('#kycReviewerPanel');
  if (reviewerPanel) reviewerPanel.textContent = appState.portfolio.kycReviewerNote || 'No reviewer note yet.';
  renderHoldings();
  renderActivity();
  renderAllocationChart();
  renderWalletState();
}

function renderDepositAddresses() {
  const btc = appState.addresses.find(item => item.asset === 'BTC');
  const usdt = appState.addresses.find(item => item.asset === 'USDT');
  if (btc) $('#btcAddress') && ($('#btcAddress').textContent = btc.address);
  if (usdt) $('#usdtAddress') && ($('#usdtAddress').textContent = usdt.address);
}

function renderKycFiles() {
  const list = $('#kycFileList');
  if (!list) return;
  if (!appState.kycFiles.length) {
    list.innerHTML = '<div class="empty-state">No KYC files uploaded yet.</div>';
    return;
  }
  list.innerHTML = appState.kycFiles.map(file => `
    <div class="file-item glass-lite">
      <div>
        <strong>${file.documentType}</strong>
        <div class="muted">${file.originalName}</div>
      </div>
      <div class="file-meta">
        <span class="pill">${file.status}</span>
        ${file.reviewerNote ? `<div class="muted small-text">${file.reviewerNote}</div>` : ''}
      </div>
    </div>
  `).join('');
}

function setupDepositActions() {
  $$('[data-copy-address]').forEach(btn => btn.addEventListener('click', async () => {
    const asset = btn.dataset.copyAddress;
    const record = appState.addresses.find(item => item.asset === asset);
    if (!record) return;
    try {
      await navigator.clipboard.writeText(record.address);
      showToast(`${asset} address copied`, 'success');
    } catch (_) {
      showToast('Clipboard unavailable in this environment', 'error');
    }
  }));
}

function setupWithdrawForm() {
  $('#withdrawForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const networkSelect = $('#withdrawNetwork');
    const payload = {
      asset: $('#withdrawAsset')?.value || 'USDT',
      network: networkSelect?.value || 'ERC-20',
      amount: $('#withdrawAmount')?.value || '0',
      address: $('#withdrawAddress')?.value?.trim() || ''
    };
    try {
      await api('/withdrawals', { method: 'POST', body: payload });
      showToast('Withdrawal request saved', 'success');
      e.target.reset();
    } catch (error) {
      showToast(error.message, 'error');
    }
  });
}

function populateSettings() {
  if (!appState.settings) return;
  $('#riskProfile') && ($('#riskProfile').value = appState.settings.riskProfile);
  $('#prefEmailAlerts') && ($('#prefEmailAlerts').checked = !!appState.settings.emailAlerts);
  $('#prefProductUpdates') && ($('#prefProductUpdates').checked = !!appState.settings.productUpdates);
  $('#prefTwoFactor') && ($('#prefTwoFactor').checked = !!appState.settings.twoFactor);
}

function setupSettingsForm() {
  $('#settingsForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      riskProfile: $('#riskProfile')?.value || 'Balanced',
      emailAlerts: $('#prefEmailAlerts')?.checked,
      productUpdates: $('#prefProductUpdates')?.checked,
      twoFactor: $('#prefTwoFactor')?.checked
    };
    try {
      await api('/settings', { method: 'PUT', body: payload });
      appState.settings = payload;
      showToast('Preferences saved', 'success');
    } catch (error) {
      showToast(error.message, 'error');
    }
  });
}

function setupQuickActions() {
  $$('[data-quick-link]').forEach(btn => btn.addEventListener('click', () => {
    window.location.href = btn.dataset.quickLink;
  }));
}

function setupAnimatedCounters() {
  $$('[data-counter]').forEach(el => {
    const target = Number(el.dataset.counter || 0);
    const prefix = el.dataset.prefix || '';
    const suffix = el.dataset.suffix || '';
    const start = performance.now();
    const duration = 900;
    const tick = (ts) => {
      const progress = Math.min((ts - start) / duration, 1);
      const value = Math.floor(progress * target);
      el.textContent = `${prefix}${value.toLocaleString()}${suffix}`;
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
}

function syncMarketDOM() {
  appState.portfolio.holdings.forEach(item => {
    const key = item.symbol.toLowerCase();
    $$(`[data-price="${key}"]`).forEach(el => el.textContent = currency(item.price));
    $$(`[data-change="${key}"]`).forEach(el => {
      el.textContent = `${item.change >= 0 ? '+' : ''}${item.change}%`;
      el.classList.remove('up', 'down');
      el.classList.add(item.change >= 0 ? 'up' : 'down');
    });
  });
}

async function fetchMarketPrices() {
  const ids = ['bitcoin', 'ethereum', 'solana', 'chainlink'].join(',');
  try {
    const response = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd&include_24hr_change=true`, { mode: 'cors' });
    const data = await response.json();
    const map = { BTC: 'bitcoin', ETH: 'ethereum', SOL: 'solana', USDC: null, LINK: 'chainlink' };
    appState.portfolio.holdings = appState.portfolio.holdings.map(item => {
      const id = map[item.symbol];
      if (!id || !data[id]) return item;
      return { ...item, price: data[id].usd, change: Number((data[id].usd_24h_change || 0).toFixed(1)) };
    });
    syncMarketDOM();
    renderDashboard();
  } catch (_) {
    syncMarketDOM();
  }
}

async function uploadKycFile(button) {
  const input = document.getElementById(button.dataset.uploadTarget);
  const file = input?.files?.[0];
  if (!file) {
    showToast('Choose a file first', 'error');
    return;
  }
  const form = new FormData();
  form.append('file', file);
  form.append('stepKey', button.dataset.stepKey || 'general');
  form.append('documentType', button.dataset.documentType || 'Document');
  try {
    await api('/kyc/files', { method: 'POST', body: form });
    showToast('KYC file uploaded', 'success');
    input.value = '';
    await loadKycFiles();
  } catch (error) {
    showToast(error.message, 'error');
  }
}

function setupKycUploads() {
  $$('[data-upload-target]').forEach(button => button.addEventListener('click', () => uploadKycFile(button)));
}

function renderKycStatusNote(kyc) {
  const box = $('#kycStatusNote');
  if (!box) return;
  const parts = [];
  if (kyc.status) parts.push(`Status: ${kyc.status}`);
  if (kyc.reviewerNote) parts.push(`Reviewer note: ${kyc.reviewerNote}`);
  if (!parts.length) {
    box.classList.add('hidden');
    return;
  }
  box.textContent = parts.join(' • ');
  box.classList.remove('hidden');
}

function setupKycStepper(initialKyc = { currentStep: 0, submitted: false, status: 'draft', reviewerNote: null }) {
  const steps = $$('.step-item');
  const screens = $$('.kyc-screen');
  const nextBtn = $('#nextStepBtn');
  const prevBtn = $('#prevStepBtn');
  const progress = $('#kycProgressFill');
  const status = $('#kycCompletionLabel');
  if (!steps.length || !screens.length) return;

  let index = initialKyc.submitted ? screens.length - 1 : Number(initialKyc.currentStep || 0);
  renderKycStatusNote(initialKyc);

  const render = () => {
    const pct = ((index + 1) / screens.length) * 100;
    steps.forEach((step, i) => {
      step.classList.toggle('active', i === index);
      step.classList.toggle('done', i < index || initialKyc.submitted);
    });
    screens.forEach((screen, i) => screen.classList.toggle('active', i === index));
    if (progress) progress.style.width = `${pct}%`;
    if (status) status.textContent = initialKyc.submitted ? 'Verification package submitted' : `Step ${index + 1} of ${screens.length}`;
    if (prevBtn) prevBtn.disabled = index === 0;
    if (nextBtn) nextBtn.textContent = index === screens.length - 1 ? 'Submit verification' : 'Continue';
  };

  steps.forEach((step, i) => step.addEventListener('click', async () => {
    index = i;
    render();
    try { await api('/kyc/draft', { method: 'PUT', body: { currentStep: index } }); } catch (error) { showToast(error.message, 'error'); }
  }));

  nextBtn?.addEventListener('click', async () => {
    if (index < screens.length - 1) {
      index += 1;
      render();
      try { await api('/kyc/draft', { method: 'PUT', body: { currentStep: index } }); } catch (error) { showToast(error.message, 'error'); }
    } else {
      try {
        await api('/kyc/submit', { method: 'POST' });
        initialKyc.submitted = true;
        initialKyc.status = 'submitted';
        render();
        renderKycStatusNote(initialKyc);
        showToast('KYC submitted for review', 'success');
        setTimeout(() => { window.location.href = 'dashboard.html'; }, 650);
      } catch (error) {
        showToast(error.message, 'error');
      }
    }
  });

  prevBtn?.addEventListener('click', async () => {
    if (index > 0) {
      index -= 1;
      render();
      try { await api('/kyc/draft', { method: 'PUT', body: { currentStep: index } }); } catch (error) { showToast(error.message, 'error'); }
    }
  });

  render();
}

async function loadKycFiles() {
  const data = await api('/kyc/files');
  appState.kycFiles = data.files;
  renderKycFiles();
}

function renderAdminOverview() {
  if (appState.admin.stats) {
    $('#adminUsersCount') && ($('#adminUsersCount').textContent = appState.admin.stats.users);
    $('#adminPendingCount') && ($('#adminPendingCount').textContent = appState.admin.stats.pendingFiles);
    $('#adminTxCount') && ($('#adminTxCount').textContent = appState.admin.stats.transactions);
  }

  const recent = $('#adminRecentUsers');
  if (recent) {
    recent.innerHTML = appState.admin.recentUsers?.length
      ? appState.admin.recentUsers.map(user => `<div class="file-item glass-lite"><div><strong>${user.first_name} ${user.last_name}</strong><div class="muted">${user.email}</div></div><span class="pill">${user.role}</span></div>`).join('')
      : '<div class="empty-state">No users yet.</div>';
  }

  const queue = $('#adminKycQueue');
  if (queue) {
    queue.innerHTML = appState.admin.pendingFiles?.length
      ? appState.admin.pendingFiles.map(file => `
        <div class="file-item glass-lite">
          <div>
            <strong>${file.documentType || file.document_type}</strong>
            <div class="muted">${file.userName || `${file.first_name} ${file.last_name}`} • ${file.userEmail || file.email}</div>
          </div>
          <div class="file-actions">
            <a class="btn btn-secondary btn-sm" href="/api/kyc/files/${file.id}/download" target="_blank">Download</a>
            <button class="btn btn-primary btn-sm" type="button" data-admin-review="${file.id}" data-review-status="approved">Approve</button>
            <button class="btn btn-danger btn-sm" type="button" data-admin-review="${file.id}" data-review-status="rejected">Reject</button>
          </div>
        </div>`).join('')
      : '<div class="empty-state">No pending KYC files.</div>';
  }

  const tbody = $('#adminUsersTableBody');
  if (tbody) {
    tbody.innerHTML = appState.admin.users.length
      ? appState.admin.users.map(user => `
        <tr>
          <td>${user.first_name} ${user.last_name}</td>
          <td>${user.email}</td>
          <td>${user.role}</td>
          <td>${user.kyc_status}</td>
          <td>${user.wallet_address ? `${user.wallet_address.slice(0, 10)}...` : '—'}</td>
          <td>${user.created_at}</td>
        </tr>`).join('')
      : '<tr><td colspan="6" class="empty-state">No users found.</td></tr>';
  }

  $$('[data-admin-review]').forEach(button => {
    button.addEventListener('click', async () => {
      const fileId = button.dataset.adminReview;
      const reviewStatus = button.dataset.reviewStatus;
      const note = window.prompt(`Optional note for ${reviewStatus}:`, '') || '';
      try {
        await api(`/admin/kyc/files/${fileId}/review`, { method: 'POST', body: { status: reviewStatus, reviewerNote: note } });
        showToast(`KYC file ${reviewStatus}`, 'success');
        await loadAdminData();
      } catch (error) {
        showToast(error.message, 'error');
      }
    });
  });
}

async function loadAdminData() {
  const [overview, users, files] = await Promise.all([
    api('/admin/overview'),
    api('/admin/users'),
    api('/admin/kyc/files')
  ]);
  appState.admin.stats = overview.stats;
  appState.admin.recentUsers = overview.recentUsers;
  appState.admin.pendingFiles = files.files.filter(file => file.status === 'uploaded');
  appState.admin.users = users.users;
  renderAdminOverview();
}

async function loadProtectedPageData() {
  const tasks = [];

  if ($('#totalBalance') || $('#activityList') || $('#holdingsTableBody')) {
    tasks.push(api('/dashboard/overview').then(data => {
      appState.user = data.user;
      appState.portfolio = data.portfolio;
      appState.activity = data.activity;
      renderDashboard();
      updateUserUI();
    }));
  }

  if ($('#transactionsTableBody')) {
    tasks.push(api('/transactions').then(data => {
      appState.transactions = data.transactions;
      renderTransactionsPage();
    }));
  }

  if ($('#btcAddress') || $('#usdtAddress')) {
    tasks.push(api('/deposit-addresses').then(data => {
      appState.addresses = data.addresses;
      renderDepositAddresses();
    }));
  }

  if ($('#settingsForm')) {
    tasks.push(api('/settings').then(data => {
      appState.settings = data.settings;
      populateSettings();
    }));
  }

  if ($$('.step-item').length) {
    tasks.push(api('/kyc').then(data => {
      appState.portfolio.kycStep = data.kyc.currentStep;
      appState.portfolio.kycSubmitted = data.kyc.submitted;
      appState.portfolio.kycStatus = data.kyc.status;
      appState.portfolio.kycReviewerNote = data.kyc.reviewerNote;
      setupKycStepper(data.kyc);
    }));
    tasks.push(loadKycFiles());
  }

  if ($('#adminUsersCount')) tasks.push(loadAdminData());

  await Promise.all(tasks.map(p => p.catch(error => showToast(error.message, 'error'))));
}

document.addEventListener('DOMContentLoaded', async () => {
  initTheme();
  setupThemeToggles();
  toggleChat();
  setupPasswordToggles();
  setupAuthForms();
  setupStrengthMeter();
  bindLogoutButtons();
  setupWalletButtons();
  setupDepositActions();
  setupWithdrawForm();
  setupSettingsForm();
  setupQuickActions();
  setupAnimatedCounters();
  setupKycUploads();

  const authOk = await requireAuthIfNeeded();
  if (document.body.dataset.protected === 'true' && !authOk) return;
  updateUserUI();
  await loadProtectedPageData();
  syncMarketDOM();
  fetchMarketPrices();
});
