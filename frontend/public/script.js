/* eslint-disable */
const API_BASE_URL = 'http://localhost:3000';

// UI Elements
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const registerBtn = document.getElementById('registerBtn');
const loginBtn = document.getElementById('loginBtn');
const googleLoginBtn = document.getElementById('googleLoginBtn');
const appleLoginBtn = document.getElementById('appleLoginBtn');
const twitterLoginBtn = document.getElementById('twitterLoginBtn');
const registerPasskeyBtn = document.getElementById('registerPasskeyBtn');
const loginPasskeyBtn = document.getElementById('loginPasskeyBtn');
const logoutBtn = document.getElementById('logoutBtn');
const messagesDiv = document.getElementById('messages');
const errorDiv = document.getElementById('error');
const userIdSpan = document.getElementById('user-id');
const userEmailSpan = document.getElementById('user-email');
const passkeyUl = document.getElementById('passkey-ul');
const identityUl = document.getElementById('identity-ul');
const linkGoogleBtn = document.getElementById('linkGoogleBtn');
const linkAppleBtn = document.getElementById('linkAppleBtn');
const linkTwitterBtn = document.getElementById('linkTwitterBtn');

let currentUserId = localStorage.getItem('userId') || null;

// --- API Request Helper ---
async function fetchAPI(url, method, body = null, auth = true) {
  const options = {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
  };
  if (body) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);
  const data = await response.json();

  if (!response.ok) {
    if (response.status === 401 && auth) {
      // アクセストークン切れの可能性があるので、リフレッシュを試みる
      const refreshed = await tryRefreshToken();
      if (refreshed) {
        // リフレッシュ成功したら再試行
        return fetchAPI(url, method, body, auth);
      }
    }
    throw new Error(
      data.message || `API request failed with status ${response.status}`,
    );
  }
  return data;
}

// --- UI Helpers ---
function displayMessage(msg, isError = false) {
  if (isError) {
    errorDiv.textContent = msg;
    messagesDiv.textContent = '';
  } else {
    messagesDiv.textContent = msg;
    errorDiv.textContent = '';
  }
}

function updateUserInfo(userId = null, email = null) {
  currentUserId = userId;
  userIdSpan.textContent = userId || 'N/A';
  userEmailSpan.textContent = email || 'N/A';

  if (userId) {
    localStorage.setItem('userId', userId);
    document.getElementById('current-user').style.display = 'block';
    document.getElementById('passkey-list').style.display = 'block';
    document.getElementById('identity-list').style.display = 'block';
    fetchIdentities();
    fetchPasskeys();
  } else {
    localStorage.removeItem('userId');
    document.getElementById('current-user').style.display = 'none';
    document.getElementById('passkey-list').style.display = 'none';
    document.getElementById('identity-list').style.display = 'none';
    passkeyUl.innerHTML = '<li>No Passkeys registered.</li>';
    identityUl.innerHTML = '<li>No linked accounts.</li>';
  }
}

// --- JWT & Refresh Token Management ---
async function tryRefreshToken() {
  try {
    displayMessage('Attempting to refresh token...');
    // refreshエンドポイントはHttpOnly Cookieのリフレッシュトークンを自動的に使用するため、bodyは不要
    await fetchAPI(`${API_BASE_URL}/auth/refresh`, 'POST', null, false);
    displayMessage('Token refreshed successfully!');
    return true;
  } catch (refreshError) {
    displayMessage(
      `Failed to refresh token: ${refreshError.message}. Please login again.`,
      true,
    );
    logout(); // リフレッシュ失敗時はログアウト
    return false;
  }
}

function logout() {
  fetchAPI(`${API_BASE_URL}/auth/logout`, 'POST', null, true)
    .then(() => displayMessage('Logged out.'))
    .catch((error) => displayMessage(`Logout failed: ${error.message}`, true))
    .finally(() => {
      updateUserInfo(null, null);
    });
}

// --- Fetch User Data ---
async function fetchProfile() {
  if (!currentUserId) {
    updateUserInfo(null, null);
    return;
  }
  try {
    const data = await fetchAPI(`${API_BASE_URL}/auth/profile`, 'GET');
    updateUserInfo(data.id, data.email);
    displayMessage('Profile loaded.');
  } catch (error) {
    displayMessage(error.message, true);
  }
}

async function fetchIdentities() {
  if (!currentUserId) {
    identityUl.innerHTML = '<li>No linked accounts.</li>';
    return;
  }
  try {
    const identities = await fetchAPI(`${API_BASE_URL}/auth/identities`, 'GET');
    identityUl.innerHTML = '';
    if (identities.length === 0) {
      identityUl.innerHTML = '<li>No linked accounts.</li>';
      return;
    }
    identities.forEach((id) => {
      const li = document.createElement('li');
      li.className = 'identity-item';
      li.innerHTML = `
                <span>Provider: ${id.provider} (${id.email || 'N/A'})</span>
                <button data-id="${id.id}" class="delete-identity-btn">Delete</button>
            `;
      identityUl.appendChild(li);
    });
    document.querySelectorAll('.delete-identity-btn').forEach((button) => {
      button.onclick = async (event) => {
        const idToDelete = event.target.dataset.id;
        try {
          await fetchAPI(
            `${API_BASE_URL}/auth/identities/${idToDelete}`,
            'DELETE',
          );
          displayMessage('Identity unlinked.');
          fetchIdentities();
        } catch (error) {
          displayMessage(error.message, true);
        }
      };
    });
  } catch (error) {
    displayMessage(error.message, true);
  }
}

async function fetchPasskeys() {
  if (!currentUserId) {
    passkeyUl.innerHTML = '<li>No Passkeys registered.</li>';
    return;
  }
  try {
    const credentials = await fetchAPI(
      `${API_BASE_URL}/auth/passkey/credentials`,
      'GET',
    );
    passkeyUl.innerHTML = '';
    if (credentials.length === 0) {
      passkeyUl.innerHTML = '<li>No Passkeys registered.</li>';
      return;
    }
    credentials.forEach((cred) => {
      const li = document.createElement('li');
      li.className = 'credential-item';
      li.innerHTML = `
                <span>ID: ${cred.credentialId.substring(0, 10)}... <br> (${cred.attestationType}, ${cred.transports.join(', ') || 'N/A'})</span>
                <button data-id="${cred.id}" class="delete-passkey-btn">Delete</button>
            `;
      passkeyUl.appendChild(li);
    });
    document.querySelectorAll('.delete-passkey-btn').forEach((button) => {
      button.onclick = async (event) => {
        const idToDelete = event.target.dataset.id;
        try {
          await fetchAPI(
            `${API_BASE_URL}/auth/passkey/credentials/${idToDelete}`,
            'DELETE',
          );
          displayMessage('Passkey deleted.');
          fetchPasskeys();
        } catch (error) {
          displayMessage(error.message, true);
        }
      };
    });
  } catch (error) {
    displayMessage(error.message, true);
  }
}

// --- Event Listeners ---
registerBtn.onclick = async () => {
  try {
    const data = await fetchAPI(
      `${API_BASE_URL}/auth/register/email-password`,
      'POST',
      {
        email: emailInput.value,
        password: passwordInput.value,
      },
      false,
    );
    displayMessage(data.message);
  } catch (error) {
    displayMessage(error.message, true);
  }
};

loginBtn.onclick = async () => {
  try {
    const data = await fetchAPI(
      `${API_BASE_URL}/auth/login/email-password`,
      'POST',
      {
        email: emailInput.value,
        password: passwordInput.value,
      },
      false,
    );
    updateUserInfo(data.userId, emailInput.value);
    displayMessage('Logged in successfully!');
    fetchProfile();
  } catch (error) {
    displayMessage(error.message, true);
  }
};

googleLoginBtn.onclick = () => {
  window.location.href = `${API_BASE_URL}/auth/google`;
};
appleLoginBtn.onclick = () => {
  window.location.href = `${API_BASE_URL}/auth/apple`;
};
twitterLoginBtn.onclick = () => {
  window.location.href = `${API_BASE_URL}/auth/twitter`;
};

logoutBtn.onclick = () => {
  logout();
};

// --- Passkey Functions ---
registerPasskeyBtn.onclick = async () => {
  if (!currentUserId) {
    displayMessage('Please login first to register a Passkey.', true);
    return;
  }
  try {
    displayMessage('Starting Passkey registration...');
    const options = await fetchAPI(
      `${API_BASE_URL}/auth/passkey/register/start`,
      'POST',
    );

    const credential = await navigator.credentials.create({
      publicKey: options,
    });

    const attestationResponse = {
      id: credential.id,
      rawId: Array.from(new Uint8Array(credential.rawId)),
      response: {
        attestationObject: Array.from(
          new Uint8Array(credential.response.attestationObject),
        ),
        clientDataJSON: Array.from(
          new Uint8Array(credential.response.clientDataJSON),
        ),
        transports: credential.response.transports || [],
      },
      type: credential.type,
      clientExtensionResults: credential.clientExtensionResults,
    };

    const clientData = JSON.parse(
      new TextDecoder().decode(attestationResponse.response.clientDataJSON),
    );
    const clientChallenge = clientData.challenge;

    const data = await fetchAPI(
      `${API_BASE_URL}/auth/passkey/register/finish`,
      'POST',
      {
        response: attestationResponse,
        challenge: clientChallenge,
      },
    );
    displayMessage(data.message);
    fetchPasskeys();
  } catch (error) {
    console.error('Passkey registration failed:', error);
    displayMessage(
      `Passkey registration failed: ${error.message || 'Unknown error'}`,
      true,
    );
  }
};

loginPasskeyBtn.onclick = async () => {
  try {
    displayMessage('Starting Passkey login...');
    const emailOrUserId = emailInput.value || undefined;

    const options = await fetchAPI(
      `${API_BASE_URL}/auth/passkey/login/start`,
      'POST',
      { emailOrUserId },
      false,
    );

    const credential = await navigator.credentials.get({ publicKey: options });

    const assertionResponse = {
      id: credential.id,
      rawId: Array.from(new Uint8Array(credential.rawId)),
      response: {
        authenticatorData: Array.from(
          new Uint8Array(credential.response.authenticatorData),
        ),
        clientDataJSON: Array.from(
          new Uint8Array(credential.response.clientDataJSON),
        ),
        signature: Array.from(new Uint8Array(credential.response.signature)),
        userHandle: credential.response.userHandle
          ? Array.from(new Uint8Array(credential.response.userHandle))
          : null,
      },
      type: credential.type,
      clientExtensionResults: credential.clientExtensionResults,
    };

    const clientData = JSON.parse(
      new TextDecoder().decode(assertionResponse.response.clientDataJSON),
    );
    const clientChallenge = clientData.challenge;

    const data = await fetchAPI(
      `${API_BASE_URL}/auth/passkey/login/finish`,
      'POST',
      {
        response: assertionResponse,
        challenge: clientChallenge,
      },
      false,
    );

    updateUserInfo(data.userId, emailInput.value || 'N/A');
    displayMessage('Logged in with Passkey successfully!');
    fetchProfile();
  } catch (error) {
    console.error('Passkey login failed:', error);
    displayMessage(
      `Passkey login failed: ${error.message || 'Unknown error'}`,
      true,
    );
  }
};

// --- Account Linking ---
linkGoogleBtn.onclick = () => {
  if (!currentUserId) {
    displayMessage('Please login first to link accounts.', true);
    return;
  }
  window.location.href = `${API_BASE_URL}/auth/identities/link/google`;
};
linkAppleBtn.onclick = () => {
  if (!currentUserId) {
    displayMessage('Please login first to link accounts.', true);
    return;
  }
  window.location.href = `${API_BASE_URL}/auth/identities/link/apple`;
};
linkTwitterBtn.onclick = () => {
  if (!currentUserId) {
    displayMessage('Please login first to link accounts.', true);
    return;
  }
  window.location.href = `${API_BASE_URL}/auth/identities/link/twitter`;
};

// --- Page Load Logic ---
window.onload = () => {
  const urlParams = new URLSearchParams(window.location.search);
  const userIdFromParam = urlParams.get('userId');
  const messageFromParam = urlParams.get('message');

  if (userIdFromParam) {
    localStorage.setItem('userId', userIdFromParam);
    currentUserId = userIdFromParam;
    displayMessage(messageFromParam || 'Login/Link successful!');
    window.history.replaceState({}, document.title, window.location.pathname);
  } else if (messageFromParam) {
    displayMessage(messageFromParam, true);
    window.history.replaceState({}, document.title, window.location.pathname);
  }

  if (currentUserId) {
    fetchProfile();
  } else {
    updateUserInfo(null, null);
  }
};
