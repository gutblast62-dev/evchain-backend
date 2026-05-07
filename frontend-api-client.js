// EVCHAIN API Client
// Replace the browser storage functions with these API calls

const API_BASE = 'https://your-backend-url.onrender.com/api'; // Change this to your backend URL
let authToken = localStorage.getItem('evchain_token') || null;

// Helper: API request
async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const response = await fetch(url, {
    ...options,
    headers
  });

  if (response.status === 401) {
    // Token expired or invalid
    localStorage.removeItem('evchain_token');
    authToken = null;
    doLogout();
    throw new Error('Session expired. Please log in again.');
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `HTTP ${response.status}`);
  }

  return response.json();
}

// AUTH
async function doLogin() {
  const u = document.getElementById('l-user').value.trim();
  const p = document.getElementById('l-pass').value;

  try {
    const data = await apiRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: u, password: p })
    });

    authToken = data.token;
    localStorage.setItem('evchain_token', authToken);
    currentUser = data.user;

    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('app').classList.add('ready');
    document.getElementById('sb-name').textContent = data.user.name;
    document.getElementById('sb-role').innerHTML = `<span class="status-dot"></span>${data.user.role === 'admin' ? 'ADMINISTRATOR' : 'PERSONNEL'}`;

    if (data.user.role === 'admin') {
      document.querySelectorAll('.admin-only').forEach(el => el.style.display = '');
      document.getElementById('btn-add-ev').style.display = '';
    }

    refreshAll();
    if (deepLinkEvidId) handleDeepLink();

  } catch (err) {
    document.getElementById('login-err').textContent = err.message;
    document.getElementById('login-err').style.display = 'block';
  }
}

// EVIDENCE
async function loadEvidence() {
  const data = await apiRequest('/evidence');
  evidence = data;
}

async function submitEvidence() {
  const caseNum = document.getElementById('f-case').value.trim();
  const desc = document.getElementById('f-desc').value.trim();
  const type = document.getElementById('f-type').value;
  const officer = document.getElementById('f-officer').value;
  const date = document.getElementById('f-date').value;

  if (!caseNum || !desc || !type || !officer || !date) {
    showToast('Please fill all required fields.', true);
    return;
  }

  try {
    const data = await apiRequest('/evidence', {
      method: 'POST',
      body: JSON.stringify({
        caseNumber: caseNum,
        description: desc,
        type,
        status: document.getElementById('f-status').value,
        assignedOfficer: officer,
        collectedBy: document.getElementById('f-collected-by').value.trim() || officer,
        dateCollected: date,
        location: document.getElementById('f-location').value.trim(),
        notes: document.getElementById('f-notes').value.trim()
      })
    });

    closeModal('add-modal');
    await refreshAll();
    showToast(`Evidence ${data.id} logged successfully.`);
  } catch (err) {
    showToast(err.message, true);
  }
}

async function deleteEvidence(id) {
  pendingDeleteId = id;
  document.getElementById('delete-evid-label').textContent = id;
  openModal('delete-modal');
}

async function confirmDelete() {
  try {
    await apiRequest(`/evidence/${pendingDeleteId}`, { method: 'DELETE' });
    closeModal('delete-modal');
    await refreshAll();
    showToast('Evidence deleted.');
  } catch (err) {
    showToast(err.message, true);
  }
}

// CUSTODY
async function submitCustody() {
  const evidId = document.getElementById('c-evid').value;
  const handler = document.getElementById('c-handler').value.trim();
  const date = document.getElementById('c-date').value;

  if (!handler || !date) {
    showToast('Please fill required fields.', true);
    return;
  }

  try {
    await apiRequest(`/evidence/${evidId}/custody`, {
      method: 'POST',
      body: JSON.stringify({
        action: document.getElementById('c-action').value,
        handler,
        date,
        notes: document.getElementById('c-notes').value.trim(),
        newStatus: document.getElementById('c-new-status').value || null
      })
    });

    closeModal('custody-modal');
    await refreshAll();
    showToast('Custody event logged.');
  } catch (err) {
    showToast(err.message, true);
  }
}

// USERS
async function loadUsers() {
  const data = await apiRequest('/users');
  users = data;
}

async function submitUser() {
  const name = document.getElementById('u-name').value.trim();
  const username = document.getElementById('u-username').value.trim().toLowerCase();
  const password = document.getElementById('u-password').value;
  const badge = document.getElementById('u-badge').value.trim();
  const role = document.getElementById('u-role').value;

  if (!name || !username || !password) {
    showToast('Please fill all required fields.', true);
    return;
  }

  try {
    if (!editingUserId) {
      await apiRequest('/users', {
        method: 'POST',
        body: JSON.stringify({ name, username, password, badge, role })
      });
      showToast(`Account "${username}" created.`);
    } else {
      await apiRequest(`/users/${editingUserId}`, {
        method: 'PUT',
        body: JSON.stringify({ name, badge, role, password: password || undefined })
      });
      showToast('Account updated.');
    }

    closeModal('user-modal');
    await refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
}

async function confirmDeleteUser() {
  try {
    await apiRequest(`/users/${pendingDeleteUserId}`, { method: 'DELETE' });
    closeModal('delete-user-modal');
    await refreshAll();
    showToast('Account removed.');
  } catch (err) {
    showToast(err.message, true);
  }
}

// DASHBOARD
async function loadStats() {
  const data = await apiRequest('/stats');
  document.getElementById('stat-total').textContent = data.total;
  document.getElementById('stat-cases').textContent = data.cases;
  document.getElementById('stat-stored').textContent = data.stored;
  document.getElementById('stat-custody').textContent = data.events;
}

// REFRESH ALL
async function refreshAll() {
  await loadEvidence();
  await loadUsers();
  await loadStats();

  const vis = getVisible();
  document.getElementById('ev-count-badge').textContent = vis.length;
  document.getElementById('user-count-badge').textContent = users.filter(u => u.role === 'personnel').length;

  renderDashboard();
  if (currentPage === 'evidence') renderEvidenceTable();
  else if (currentPage === 'custody') renderCustodyView();
  else if (currentPage === 'users') renderUsersTable();
}

// QR CODE
async function showQR(id) {
  const ev = evidence.find(e => e.id === id);
  if (!ev) return;

  try {
    const data = await apiRequest(`/evidence/${id}/qr`, { method: 'POST' });
    document.getElementById('qr-evid-label').textContent = id;
    document.getElementById('qr-case-label').textContent = `Case: ${ev.case_number}`;
    document.getElementById('qr-url-display').textContent = data.url;

    const wrap = document.getElementById('qr-canvas-wrap');
    wrap.innerHTML = '';
    new QRCode(wrap, {
      text: data.url,
      width: 180,
      height: 180,
      colorDark: '#000000',
      colorLight: '#ffffff',
      correctLevel: QRCode.CorrectLevel.M
    });

    openModal('qr-modal');
  } catch (err) {
    showToast(err.message, true);
  }
}

// Initialize: Check for stored token on load
(async () => {
  const params = new URLSearchParams(window.location.search);
  const evid = params.get('evid');
  if (evid) deepLinkEvidId = decodeURIComponent(evid);

  if (authToken) {
    try {
      // Verify token is still valid by loading stats
      await loadStats();
      // If successful, we're logged in
      // Note: You'd need a /me endpoint to get user details, or store them in localStorage
    } catch {
      authToken = null;
      localStorage.removeItem('evchain_token');
    }
  }
})();
