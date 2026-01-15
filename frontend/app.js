// S3 Access Manager - Frontend Application
// Configuration
const CONFIG = {
    gatewayUrl: '',  // Empty string since frontend and API are on same origin
    oidcStorage: 'oidc_config',
    tokenStorage: 'auth_token',
    userStorage: 'user_info'
};

// State Management
const state = {
    token: null,
    userInfo: null,
    currentBucket: null,
    currentPrefix: '',
    credentials: [],
    selectedCredential: null,  // Selected credential for S3 operations
    actualIsAdmin: false,      // Actual admin status from backend
    simulatedIsAdmin: true,    // Simulated admin status (togglable)
    loadingCount: 0            // Counter for concurrent API calls
};

// Loading Spinner Functions
function showLoadingSpinner() {
    state.loadingCount++;
    const spinner = document.getElementById('loading-spinner');
    if (spinner) {
        spinner.style.display = 'flex';
    }
}

function hideLoadingSpinner() {
    state.loadingCount--;
    if (state.loadingCount <= 0) {
        state.loadingCount = 0;
        const spinner = document.getElementById('loading-spinner');
        if (spinner) {
            spinner.style.display = 'none';
        }
    }
}

// Initialize App
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

function initializeApp() {
    // Check if this is an OIDC callback
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const oauthState = urlParams.get('state');
    const error = urlParams.get('error');
    
    if (error) {
        showToast('Authentication error: ' + (urlParams.get('error_description') || error), 'error');
        window.history.replaceState({}, document.title, window.location.pathname);
        showLoginScreen();
        setupEventListeners();
        return;
    }
    
    if (code && oauthState) {
        // Handle OIDC callback
        handleOIDCCallback(code, oauthState);
        return;
    }
    
    // Check if user is already logged in
    const storedToken = localStorage.getItem(CONFIG.tokenStorage);
    const storedUser = localStorage.getItem(CONFIG.userStorage);
    
    if (storedToken && storedUser) {
        state.token = storedToken; // This is the access token
        state.userInfo = JSON.parse(storedUser);
        
        // Validate token by checking gateway health with auth
        validateTokenAndShowDashboard();
    } else {
        // Clear any old OIDC state when showing login screen
        sessionStorage.removeItem('oauth_state');
        sessionStorage.removeItem('pkce_verifier');
        showLoginScreen();
    }
    
    setupEventListeners();
}

async function validateTokenAndShowDashboard() {
    try {
        // Try to access credentials endpoint to validate token and get user info
        const response = await apiCall('/settings/credentials');
        
        // Token is valid, update user info and roles from backend
        if (response.user_info) {
            state.userInfo = {
                ...state.userInfo,
                subject: response.user_info.subject,
                email: response.user_info.email,
                name: response.user_info.email // Use email as display name
            };
            localStorage.setItem(CONFIG.userStorage, JSON.stringify(state.userInfo));
        }
        
        // Set user roles from the response
        const userRoles = response.user_roles || [];
        state.userRoles = userRoles;
        state.actualIsAdmin = response.is_admin || false;
        
        showDashboard();
        const username = state.userInfo.name || state.userInfo.email || state.userInfo.sub || 'User';
        showToast(`Welcome back ${username}!`, 'success');
    } catch (error) {
        // Token is invalid or network error, clear and show login
        console.error('Token validation failed:', error);
        localStorage.removeItem(CONFIG.tokenStorage);
        localStorage.removeItem(CONFIG.userStorage);
        localStorage.removeItem('refresh_token');
        state.token = null;
        state.userInfo = null;
        showLoginScreen();
    }
}

async function handleOIDCCallback(code, receivedState) {
    try {
        showToast('Processing authentication...', 'info');
        
        // Verify state to prevent CSRF
        const storedState = sessionStorage.getItem('oauth_state');
        console.log('Stored state:', storedState);
        console.log('Received state:', receivedState);
        if (storedState !== receivedState) {
            console.error('State mismatch - stored:', storedState, 'received:', receivedState);
            throw new Error('Invalid state parameter - possible CSRF attack');
        }
        
        // Get stored OIDC config
        const oidcConfig = JSON.parse(localStorage.getItem(CONFIG.oidcStorage));
        console.log('OIDC config:', oidcConfig);
        if (!oidcConfig) {
            throw new Error('OIDC configuration not found');
        }
        
        // Get PKCE verifier
        const codeVerifier = sessionStorage.getItem('pkce_verifier');
        console.log('Code verifier:', codeVerifier);
        if (!codeVerifier) {
            throw new Error('PKCE verifier not found');
        }
        
        // Discover token endpoint
        const discovery = await discoverOIDCEndpoints(oidcConfig.issuer);
        
        // Exchange authorization code for tokens
        const redirectUri = window.location.origin + '/callback';
        const tokenParams = new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: redirectUri,
            client_id: oidcConfig.client_id || oidcConfig.clientId,
            code_verifier: codeVerifier
        });
        
        const tokenResponse = await fetch(discovery.token_endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: tokenParams.toString()
        });
        
        if (!tokenResponse.ok) {
            const errorData = await tokenResponse.json().catch(() => ({}));
            throw new Error(errorData.error_description || 'Token exchange failed');
        }
        
        const tokens = await tokenResponse.json();
        
        console.log('Token exchange successful');
        console.log('Full token response:', tokens);
        console.log('Access token present?', !!tokens.access_token);
        console.log('ID token present?', !!tokens.id_token);
        
        // OAuth2 standard: Use access token for API authentication
        // Backend will validate it via /userinfo endpoint
        if (!tokens.access_token) {
            throw new Error('No access token received from token exchange');
        }
        
        console.log('Storing access token, first 30 chars:', tokens.access_token.substring(0, 30));
        state.token = tokens.access_token;
        
        // Parse ID token temporarily for initial display (backend will provide authoritative user info)
        const userInfo = parseJWT(tokens.id_token);
        state.userInfo = userInfo;
        
        localStorage.setItem(CONFIG.tokenStorage, tokens.access_token);
        localStorage.setItem(CONFIG.userStorage, JSON.stringify(userInfo));
        
        // If refresh token is available, store it
        if (tokens.refresh_token) {
            localStorage.setItem('refresh_token', tokens.refresh_token);
        }
        
        // Store ID token for reference (optional)
        if (tokens.id_token) {
            localStorage.setItem('id_token', tokens.id_token);
        }
        
        console.log('Tokens stored, fetching user info from backend...');
        
        // Get authoritative user info from backend (respects OIDC_USER_CLAIM)
        try {
            const response = await apiCall('/settings/credentials');
            if (response.user_info) {
                const backendUserInfo = {
                    subject: response.user_info.subject,
                    email: response.user_info.email,
                    name: response.user_info.email, // Use email as display name
                    sub: response.user_info.subject
                };
                state.userInfo = backendUserInfo;
                localStorage.setItem(CONFIG.userStorage, JSON.stringify(backendUserInfo));
                console.log('User info updated from backend:', backendUserInfo.email);
            }
        } catch (error) {
            console.error('Failed to get user info from backend, using JWT data:', error);
        }
        
        // Clean up
        sessionStorage.removeItem('pkce_verifier');
        sessionStorage.removeItem('oauth_state');
        window.history.replaceState({}, document.title, window.location.pathname);
        
        // Setup event listeners
        setupEventListeners();
        
        // Show dashboard without triggering data loads yet
        document.getElementById('login-screen').classList.remove('active');
        document.getElementById('dashboard-screen').classList.add('active');
        
        // Update user info display
        if (state.userInfo) {
            document.getElementById('user-info').textContent = 
                state.userInfo.name || state.userInfo.email || state.userInfo.sub || 'User';
        }
        
        // Show welcome message with username
        const username = state.userInfo.name || state.userInfo.email || state.userInfo.sub || 'User';
        showToast(`Welcome ${username}!`, 'success');
        
        // Load data after a short delay to ensure UI is ready
        setTimeout(() => {
            loadBuckets();
            // loadCredentials(); // Removed to load only when tab is selected, similar to users
            // Add redirect to root to simulate refresh
            window.location.href = '/';
        }, 500);
        
    } catch (error) {
        console.error('OIDC callback error:', error);
        showToast('Authentication failed: ' + error.message, 'error');
        
        // Clean up and show login
        sessionStorage.removeItem('pkce_verifier');
        sessionStorage.removeItem('oauth_state');
        window.history.replaceState({}, document.title, window.location.pathname);
        showLoginScreen();
        setupEventListeners();
    }
}

function parseJWT(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        
        return JSON.parse(jsonPayload);
    } catch (error) {
        console.error('Failed to parse JWT:', error);
        return {};
    }
}

function setupEventListeners() {
    // Login
    document.getElementById('login-btn').addEventListener('click', handleLogin);
    
    // Logout
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    
    // Admin mode toggle
    const adminToggle = document.getElementById('admin-mode-toggle');
    if (adminToggle) {
        adminToggle.addEventListener('change', (e) => {
            state.simulatedIsAdmin = e.target.checked;
            const label = document.getElementById('admin-mode-label');
            if (label) {
                label.textContent = e.target.checked ? 'Admin View' : 'Regular User View';
            }
            updateUIForAdminMode();
            // Reload current tab to reflect changes
            const activeTab = document.querySelector('.tab.active');
            if (activeTab) {
                switchTab(activeTab.dataset.tab);
            }
        });
    }
    
    // Secret key visibility toggle
    const toggleSecretBtn = document.getElementById('toggle-secret-visibility');
    if (toggleSecretBtn) {
        toggleSecretBtn.addEventListener('click', toggleSecretKeyVisibility);
    }
    
    // Tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });
    
    // Credentials
    document.getElementById('create-credential-btn').addEventListener('click', async () => {
        showModal('create-credential-modal');
        await loadAvailableRolesForCredential();
    });
    document.getElementById('update-credentials-btn').addEventListener('click', updateAllCredentials);
    document.getElementById('confirm-create-credential').addEventListener('click', handleCreateCredential);
    document.getElementById('confirm-save-policy').addEventListener('click', savePolicy);
    document.getElementById('confirm-save-role').addEventListener('click', saveRole);
    
    // Buckets
    document.getElementById('create-bucket-btn').addEventListener('click', () => {
        showModal('create-bucket-modal');
    });
    document.getElementById('confirm-create-bucket').addEventListener('click', handleCreateBucket);
    
    // Modal close buttons
    document.querySelectorAll('.modal-close, .modal-cancel').forEach(btn => {
        btn.addEventListener('click', () => hideModals());
    });
    
    // Policy JSON change listener - invalidate validation when content changes
    document.getElementById('policy-json').addEventListener('input', () => {
        if (state.policyValidated) {
            document.getElementById('confirm-save-policy').disabled = true;
            document.getElementById('policy-validation').innerHTML = '<span style="color: #f59e0b;">⚠ Content changed - please validate again</span>';
            state.policyValidated = false;
        }
    });
}

// Screen Management
function showLoginScreen() {
    document.getElementById('login-screen').classList.add('active');
    document.getElementById('dashboard-screen').classList.remove('active');
    
    // Fetch OIDC configuration from backend
    fetchOIDCConfiguration();
}

async function fetchOIDCConfiguration() {
    try {
        const response = await fetch(`${CONFIG.gatewayUrl}/oidc-config`);
        if (!response.ok) {
            throw new Error('Failed to fetch OIDC configuration');
        }
        
        const oidcConfig = await response.json();
              
        // Store configuration
        localStorage.setItem(CONFIG.oidcStorage, JSON.stringify(oidcConfig));
        
        // Set hidden fields
        document.getElementById('oidc-issuer').value = oidcConfig.issuer || '';
        document.getElementById('client-id').value = oidcConfig.client_id || '';
        
        // Configuration is ready
        console.log('OIDC configuration loaded:', oidcConfig.issuer);
    } catch (error) {
        console.error('Failed to fetch OIDC config:', error);
        showToast('Cannot connect to authentication server', 'error');
        
        // Fall back to checking localStorage
        const savedOIDC = localStorage.getItem(CONFIG.oidcStorage);
        if (savedOIDC) {
            const config = JSON.parse(savedOIDC);
            document.getElementById('oidc-issuer').value = config.issuer || '';
            document.getElementById('client-id').value = config.client_id || config.clientId || '';
        }
    }
}

function showDashboard() {
    document.getElementById('login-screen').classList.remove('active');
    document.getElementById('dashboard-screen').classList.add('active');
    
    // Update user info display
    if (state.userInfo) {
        const userEmail = state.userInfo.email || state.userInfo.sub || 'User';
        const roles = state.userRoles && state.userRoles.length > 0 
            ? ` (${state.userRoles.join(', ')})` 
            : '';
        document.getElementById('user-info').textContent = userEmail + roles;
    }
    
    // Load initial data
    checkGatewayHealth();
    loadCredentials();
}

// Update UI based on admin mode toggle
function updateUIForAdminMode() {
    const isAdmin = state.actualIsAdmin && state.simulatedIsAdmin;
    
    // Update all admin-only elements
    document.querySelectorAll('.admin-only').forEach(el => {
        el.style.display = isAdmin ? '' : 'none';
    });
}

// OIDC Helper Functions
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
}

async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return base64URLEncode(new Uint8Array(hash));
}

function base64URLEncode(buffer) {
    const base64 = btoa(String.fromCharCode(...buffer));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function discoverOIDCEndpoints(issuer) {
    try {
        const response = await fetch(`${issuer}/.well-known/openid-configuration`);
        if (!response.ok) {
            throw new Error('Failed to discover OIDC endpoints');
        }
        const config = await response.json();
        
        // Ensure endpoints use HTTPS if the current page is served over HTTPS
        if (window.location.protocol === 'https:') {
            for (const key in config) {
                if (typeof config[key] === 'string' && config[key].startsWith('http://')) {
                    config[key] = config[key].replace('http://', 'https://');
                }
            }
        }
        
        return config;
    } catch (error) {
        console.error('OIDC discovery failed:', error);
        throw error;
    }
}

// Authentication
async function handleLogin() {
    const issuer = document.getElementById('oidc-issuer').value;
    const clientId = document.getElementById('client-id').value;
    
    if (!issuer || !clientId) {
        showToast('OIDC configuration is incomplete', 'error');
        return;
    }
    
    try {
        showToast('Initiating OIDC authentication...', 'info');
        
        // Get OIDC configuration from localStorage
        const storedConfig = JSON.parse(localStorage.getItem(CONFIG.oidcStorage) || '{}');
        const scopes = storedConfig.scopes || 'openid profile email';
        
        // Store OIDC configuration for callback
        const oidcConfig = {
            issuer: issuer,
            client_id: clientId,
            scopes: scopes
        };
        localStorage.setItem(CONFIG.oidcStorage, JSON.stringify(oidcConfig));
        
        // Discover OIDC endpoints
        const discoveredConfig = await discoverOIDCEndpoints(issuer);
        
        // Generate PKCE parameters
        const codeVerifier = generateCodeVerifier();
        const codeChallenge = await generateCodeChallenge(codeVerifier);
        
        // Generate state for CSRF protection
        const state = base64URLEncode(crypto.getRandomValues(new Uint8Array(16)));
        
        // Store PKCE parameters and state
        sessionStorage.setItem('pkce_verifier', codeVerifier);
        sessionStorage.setItem('oauth_state', state);
        
        // Build authorization URL
        const redirectUri = window.location.origin + '/callback';
        const authParams = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: scopes,
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        
        const authUrl = `${discoveredConfig.authorization_endpoint}?${authParams.toString()}`;
        
        // Redirect to OIDC provider
        window.location.href = authUrl;
        
    } catch (error) {
        console.error('Login failed:', error);
        showToast('Failed to initiate login: ' + error.message, 'error');
    }
}

function handleLogout() {
    state.token = null;
    state.userInfo = null;
    localStorage.removeItem(CONFIG.tokenStorage);
    localStorage.removeItem(CONFIG.userStorage);
    localStorage.removeItem('refresh_token');
    
    showLoginScreen();
    showToast('Logged out successfully', 'success');
}

// Tab Navigation
function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabName);
    });
    
    // Update tab panels
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    // Load tab-specific data
    switch(tabName) {
        case 'credentials':
            loadCredentials();
            break;
        case 'policies':
            loadPolicies();
            break;
        case 'roles':
            loadRoles();
            break;
        case 'buckets':
            loadBucketsCredentialSelector();
            loadBuckets();
            break;
        case 'users':
            loadUsers();
            break;
    }
}

// Utility Functions
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// API Calls
async function apiCall(endpoint, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (state.token) {
        headers['Authorization'] = `Bearer ${state.token}`;
        console.log('API call with auth:', endpoint);
    } else {
        console.log('API call without auth:', endpoint);
    }
    
    // Add credential header for S3 operations (buckets, objects)
    if (state.selectedCredential && (endpoint.startsWith('/s3/') || endpoint.includes('/settings/buckets'))) {
        headers['X-S3-Credential-AccessKey'] = state.selectedCredential;
        console.log('Adding credential header:', state.selectedCredential);
    }
    
    showLoadingSpinner();
    
    try {
        const response = await fetch(`${CONFIG.gatewayUrl}${endpoint}`, {
            ...options,
            headers
        });
        
        if (!response.ok) {
            // Try to parse error response
            const contentType = response.headers.get('content-type');
            let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
            
            if (contentType && contentType.includes('application/json')) {
                try {
                    const errorData = await response.json();
                    console.error('API error response:', errorData);
                    
                    // Handle 401 Unauthorized - token expired or invalid
                    if (response.status === 401) {
                        console.log('Authentication failed (401):', endpoint);
                        
                        // Only clear session and show message if we're not in the middle of initial login
                        const hasStoredToken = localStorage.getItem(CONFIG.tokenStorage);
                        if (hasStoredToken) {
                            localStorage.removeItem(CONFIG.tokenStorage);
                            localStorage.removeItem(CONFIG.userStorage);
                            localStorage.removeItem('refresh_token');
                            state.token = null;
                            state.userInfo = null;
                            
                            // Only show session expired if we're currently on dashboard
                            const dashboardActive = document.getElementById('dashboard-screen').classList.contains('active');
                            if (dashboardActive) {
                                showLoginScreen();
                                showToast('Session expired. Please sign in again.', 'error');
                            }
                        }
                        throw new Error('Authentication required');
                    }
                    
                    // Handle 403 Forbidden with detailed error
                    if (response.status === 403 && errorData.error) {
                        if (errorData.your_roles && errorData.requested) {
                            errorMessage = `${errorData.error}\nYour roles: ${errorData.your_roles.join(', ')}\nRequested: ${errorData.requested.join(', ')}`;
                        } else {
                            errorMessage = errorData.error;
                        }
                    } else if (errorData.error) {
                        errorMessage = errorData.error;
                    }
                } catch (parseError) {
                    console.error('Failed to parse error response:', parseError);
                }
            }
            
            throw new Error(errorMessage);
        }
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const result = await response.json();
            hideLoadingSpinner();
            return result;
        }
        const result = await response.text();
        hideLoadingSpinner();
        return result;
    } catch (error) {
        console.error('API call failed:', error);
        hideLoadingSpinner();
        throw error;
    }
}

// Gateway Health Check
async function checkGatewayHealth() {
    try {
        const response = await fetch(`${CONFIG.gatewayUrl}/health`);
        const data = await response.json();
        
        const statusEl = document.getElementById('connection-status');
        statusEl.classList.add('connected');
        statusEl.querySelector('span:last-child').textContent = 'Connected';
        
        document.getElementById('api-version').textContent = data.version || '1.0.0';
    } catch {
        showToast('Cannot connect to gateway', 'error');
    }
}

// Credentials Management
async function loadCredentials() {
    const listEl = document.getElementById('credentials-list');
    listEl.innerHTML = '<div class="empty-state">Loading credentials...</div>';
    
    try {
        const response = await apiCall('/settings/credentials');
        const credentials = response.credentials || [];
        const userRoles = response.user_roles || [];
        const userInfo = response.user_info || {};
        const isAdmin = response.is_admin || false;
        
        state.credentials = credentials;
        state.userRoles = userRoles;
        state.actualIsAdmin = isAdmin;
        state.isAdmin = isAdmin; // Keep for backward compatibility
        
        // Show/hide admin toggle (only for actual admins)
        const toggleContainer = document.getElementById('admin-toggle-container');
        if (toggleContainer) {
            toggleContainer.style.display = isAdmin ? 'flex' : 'none';
            // Initialize toggle state
            const toggle = document.getElementById('admin-mode-toggle');
            if (toggle && state.actualIsAdmin) {
                toggle.checked = state.simulatedIsAdmin;
            }
        }
        
        // Update UI based on admin mode
        updateUIForAdminMode();
        
        // Update stored user info with backend's authoritative data
        if (userInfo.subject || userInfo.email) {
            state.userInfo = {
                ...state.userInfo,
                subject: userInfo.subject,
                email: userInfo.email,
                name: userInfo.email // Use email as display name
            };
            localStorage.setItem(CONFIG.userStorage, JSON.stringify(state.userInfo));
            
            // Update user info display with roles
            const userEmail = userInfo.email || userInfo.subject || 'User';
            const rolesText = userRoles.length > 0 ? ` (${userRoles.join(', ')})` : '';
            document.getElementById('user-info').textContent = userEmail + rolesText;
        }
        
        if (credentials.length === 0) {
            listEl.innerHTML = `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                    </svg>
                    <p>No credentials yet</p>
                    <p style="font-size: 0.875rem; margin-top: 0.5rem;">Create your first credential to get started</p>
                </div>
            `;
        } else {
            listEl.innerHTML = credentials.map(cred => `
                <div class="credential-card">
                    <div class="credential-info">
                        <h4>${cred.name || cred.id} ${getBackendStatusBadge(cred.backend_status)}</h4>
                        <div class="credential-meta">
                            <span>Access Key: ${cred.access_key || '***'}</span> •
                            <span>Created: ${new Date(cred.created_at).toLocaleDateString()}</span>
                            ${cred.roles && cred.roles.length > 0 ? ` • <span>Roles: ${cred.roles.join(', ')}</span>` : ''}
                        </div>
                    </div>
                    <div class="credential-actions">
                        <button class="btn-icon" onclick="inspectCredential('${cred.access_key}')" title="Inspect">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                        </button>
                        <button class="btn-icon" onclick="copyAWSConfig('${cred.name}', '${cred.access_key}')" title="Copy AWS Config">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                                <polyline points="14 2 14 8 20 8"></polyline>
                                <line x1="16" y1="13" x2="8" y2="13"></line>
                                <line x1="16" y1="17" x2="8" y2="17"></line>
                                <polyline points="10 9 9 9 8 9"></polyline>
                            </svg>
                        </button>
                        <button class="btn-icon" onclick="copyCredential('${cred.access_key}')" title="Copy Access Key">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                            </svg>
                        </button>
                        <button class="btn-icon btn-danger" onclick="deleteCredential('${cred.access_key}')" title="Delete">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polyline points="3 6 5 6 21 6"></polyline>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                            </svg>
                        </button>
                    </div>
                </div>
            `).join('');
        }
    } catch (error) {
        listEl.innerHTML = `
            <div class="empty-state">
                <p style="color: var(--danger-color);">Failed to load credentials</p>
                <p style="font-size: 0.875rem; margin-top: 0.5rem;">${error.message}</p>
            </div>
        `;
    }
}

async function loadAvailableRolesForCredential() {
    const container = document.getElementById('cred-roles');
    if (!container) return;
    
    container.innerHTML = '<p style="color: var(--text-secondary);">Loading roles...</p>';
    
    try {
        const response = await apiCall('/settings/roles');
        let roles = response.roles || [];
        
        // Use simulated admin status for filtering
        const isAdmin = state.actualIsAdmin && state.simulatedIsAdmin;
        
        // Filter roles based on user roles
        // Admin sees all roles, regular users see only their assigned roles
        if (!isAdmin && state.userRoles) {
            roles = roles.filter(role => state.userRoles.includes(role.name));
        }
        
        container.innerHTML = '';
        
        if (roles.length > 0) {
            roles.forEach(role => {
                const label = document.createElement('label');
                label.style.display = 'flex';
                label.style.alignItems = 'center';
                label.style.padding = '0.25rem 0';
                label.style.cursor = 'pointer';
                label.style.borderRadius = '4px';
                label.style.transition = 'background 0.2s';
                label.onmouseover = () => label.style.background = 'var(--hover-bg)';
                label.onmouseout = () => label.style.background = 'transparent';
                
                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.value = role.name;
                checkbox.className = 'role-checkbox';
                checkbox.style.flex = '0 0 10%';
                checkbox.style.margin = '0';
                
                const textDiv = document.createElement('div');
                textDiv.style.flex = '1';
                textDiv.style.paddingLeft = '0.5rem';
                
                const span = document.createElement('span');
                span.style.fontWeight = 'bold';
                span.textContent = role.name.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                
                textDiv.appendChild(span);
                
                // Add description if available
                if (role.description) {
                    const desc = document.createElement('span');
                    desc.style.color = 'var(--text-secondary)';
                    desc.style.fontSize = '0.75rem';
                    desc.style.marginLeft = '0.5rem';
                    desc.textContent = `— ${role.description}`;
                    textDiv.appendChild(desc);
                }
                
                label.appendChild(checkbox);
                label.appendChild(textDiv);
                container.appendChild(label);
            });
        } else {
            container.innerHTML = '<p style="color: var(--text-secondary); font-size: 0.875rem;">No roles available</p>';
        }
    } catch (error) {
        console.error('Failed to load roles:', error);
        container.innerHTML = '<p style="color: var(--danger-color); font-size: 0.875rem;">Failed to load roles</p>';
    }
}

async function inspectCredential(accessKey) {
    const cred = state.credentials.find(c => c.access_key === accessKey);
    if (!cred) {
        showToast('Credential not found', 'error');
        return;
    }
    
    // Fetch full credential details including secret key
    try {
        const response = await apiCall(`/settings/credentials/${accessKey}`);
        const fullCred = response.credential;
        
        document.getElementById('inspect-cred-name').textContent = fullCred.name || fullCred.id;
        document.getElementById('inspect-cred-access-key').textContent = fullCred.access_key;
        document.getElementById('inspect-cred-created').textContent = new Date(fullCred.created_at).toLocaleString();
        
        // Store secret key for toggle functionality
        state.currentInspectSecretKey = fullCred.secret_key || null;
        state.secretKeyVisible = false;
        
        // Display secret key as asterisks initially
        const secretKeyEl = document.getElementById('inspect-cred-secret-key');
        if (fullCred.secret_key) {
            secretKeyEl.textContent = '••••••••••••••••••••••••••••••••';
            secretKeyEl.style.color = '';
        } else {
            secretKeyEl.textContent = 'Not available';
            secretKeyEl.style.color = 'var(--text-secondary)';
        }
        
        // Show roles as badges
        const policiesContainer = document.getElementById('inspect-cred-policies');
        if (fullCred.roles && fullCred.roles.length > 0) {
            policiesContainer.innerHTML = fullCred.roles.map(role => `
                <span style="background-color: var(--primary-color); color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.875rem;">
                    ${role}
                </span>
            `).join('');
        } else {
            policiesContainer.innerHTML = '<span style="color: var(--text-secondary);">No roles assigned</span>';
        }
        
        // Show description if available
        const descGroup = document.getElementById('inspect-cred-description-group');
        if (fullCred.description) {
            document.getElementById('inspect-cred-description').textContent = fullCred.description;
            descGroup.style.display = 'block';
        } else {
            descGroup.style.display = 'none';
        }
        
        showModal('inspect-credential-modal');
    } catch (error) {
        console.error('Failed to fetch credential details:', error);
        showToast('Failed to load credential details: ' + error.message, 'error');
    }
}


async function handleCreateCredential() {
    const name = document.getElementById('cred-name').value;
    const checkboxes = document.querySelectorAll('.role-checkbox:checked');
    const selectedRoles = Array.from(checkboxes).map(cb => cb.value);
    const description = document.getElementById('cred-description')?.value || '';
    
    console.log('handleCreateCredential called', { name, selectedRoles, description });
    
    if (!name) {
        showToast('Please enter a credential name', 'error');
        return;
    }
    
    if (selectedRoles.length === 0) {
        showToast('Please select at least one role', 'error');
        return;
    }
    
    try {
        console.log('Sending POST request to create credential');
        const result = await apiCall('/settings/credentials', {
            method: 'POST',
            body: JSON.stringify({
                name,
                description,
                roles: selectedRoles  // Send array of selected roles
            })
        });
        
        console.log('Credential created successfully', result);
        hideModals();
        showToast('Credential created successfully! Access key copied to clipboard.', 'success');
        
        // Copy access key, secret key, and session token to clipboard
        if (result.credential && result.credential.secret_key) {
            let credInfo = `Access Key: ${result.credential.access_key}\nSecret Key: ${result.credential.secret_key}`;
            if (result.credential.session_token) {
                credInfo += `\nSession Token: ${result.credential.session_token}`;
            }
            navigator.clipboard.writeText(credInfo);
        }
        
        loadCredentials();
        
        // Clear form
        document.getElementById('cred-name').value = '';
        if (document.getElementById('cred-description')) {
            document.getElementById('cred-description').value = '';
        }
    } catch (error) {
        console.error('Failed to create credential:', error);
        showToast('Failed to create credential: ' + error.message, 'error');
    }
}

async function updateAllCredentials() {
    if (!confirm('This will update all existing credentials with their current role policies. Continue?')) {
        return;
    }
    
    try {
        showToast('Updating credentials...', 'info');
        const response = await apiCall('/settings/credentials/update-all', { method: 'POST' });
        
        if (response.updated_count > 0) {
            let message = `Successfully updated ${response.updated_count} credential(s)`;
            if (response.roles_updated_count > 0) {
                message += ` and cleaned up roles for ${response.roles_updated_count} credential(s)`;
            }
            showToast(message, 'success');
        } else if (response.total_count > 0) {
            showToast('No credentials needed updating', 'info');
        } else {
            showToast('No credentials found', 'info');
        }
        
        // Reload credentials to show updated info
        loadCredentials();
    } catch (error) {
        showToast('Failed to update credentials: ' + error.message, 'error');
    }
}

async function deleteCredential(id) {
    if (!confirm('Are you sure you want to delete this credential?')) {
        return;
    }
    
    try {
        await apiCall(`/settings/credentials/${id}`, { method: 'DELETE' });
        showToast('Credential deleted', 'success');
        loadCredentials();
    } catch (error) {
        showToast('Failed to delete credential: ' + error.message, 'error');
    }
}

async function copyCredential(accessKey) {
    try {
        const response = await apiCall(`/settings/credentials/${accessKey}`);
        const cred = response.credential;
        
        if (cred) {
            const text = `Access Key: ${cred.access_key}\nSecret Key: ${cred.secret_key || 'Not available'}`;
            await navigator.clipboard.writeText(text);
            if (cred.secret_key) {
                showToast('Credential copied to clipboard', 'success');
            } else {
                showToast('Credential copied (secret key not available)', 'info');
            }
        }
    } catch (error) {
        console.error('Failed to copy credential:', error);
        showToast('Failed to copy credential', 'error');
    }
}

async function copyAWSConfig(credName, accessKey) {
    try {
        const response = await apiCall(`/settings/credentials/${accessKey}`);
        const cred = response.credential;
        
        if (!cred) {
            showToast('Credential not found', 'error');
            return;
        }

        // Get S3 endpoint from current location or use default
        const s3Endpoint = 'https://object-acc.data.surf.nl';
        const region = 'us-east-1';  // Use proper AWS region instead of 'default'
        
        // Create profile name from credential name (sanitize for use in config)
        const profileName = credName.toLowerCase().replace(/[^a-z0-9-]/g, '-');
        
        // Generate AWS config content for ~/.aws/config and ~/.aws/credentials
        // Use the actual secret key from the credential
        const configContent = `# AWS Config for ${credName}
# Paste this into your ~/.aws/config file

[profile ${profileName}]
region = ${region}
endpoint_url = ${s3Endpoint}
signature_version = s3v4
payload_signing_enabled = true
addressing_style = path

# Also add this to your ~/.aws/credentials file:
# [${profileName}]
# aws_access_key_id = ${cred.access_key}
# aws_secret_access_key = ${cred.secret_key || 'YOUR_SECRET_KEY_HERE'}

# Usage examples:
# aws s3 ls --profile ${profileName}
# aws s3 mb s3://my-bucket --profile ${profileName}
# aws s3 cp file.txt s3://my-bucket/ --profile ${profileName}
`;

        // Also generate the credentials content
        const credentialsContent = `# AWS Credentials for ${credName}
# Paste this into your ~/.aws/credentials file

[${profileName}]
aws_access_key_id = ${cred.access_key}
aws_secret_access_key = ${cred.secret_key || 'YOUR_SECRET_KEY_HERE'}
`;

        console.log('Copying AWS config to clipboard:', configContent);
        console.log('Credentials content:', credentialsContent);

        // Copy both config and credentials to clipboard
        const fullContent = configContent + '\n' + credentialsContent;

        // Copy to clipboard
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(fullContent);
            console.log('Successfully copied to clipboard');
            if (!cred.secret_key) {
                showToast('AWS config copied! Note: Secret key not available - replace YOUR_SECRET_KEY_HERE', 'info');
            } else {
                showToast('AWS config and credentials copied to clipboard - paste into ~/.aws/config and ~/.aws/credentials', 'success');
            }
        } else {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = fullContent;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                console.log('Copied using fallback method');
                if (!cred.secret_key) {
                    showToast('AWS config copied! Note: Secret key not available - replace YOUR_SECRET_KEY_HERE', 'info');
                } else {
                    showToast('AWS config and credentials copied to clipboard - paste into ~/.aws/config and ~/.aws/credentials', 'success');
                }
            } catch (err) {
                console.error('Fallback copy failed:', err);
                showToast('Failed to copy to clipboard', 'error');
            }
            document.body.removeChild(textArea);
        }
    } catch (error) {
        console.error('Failed to copy AWS config:', error);
        showToast('Failed to copy AWS config', 'error');
    }
}

function toggleSecretKeyVisibility() {
    const secretKeyEl = document.getElementById('inspect-cred-secret-key');
    const iconEl = document.getElementById('secret-eye-icon');
    
    if (!state.currentInspectSecretKey) {
        showToast('Secret key not available', 'info');
        return;
    }
    
    state.secretKeyVisible = !state.secretKeyVisible;
    
    if (state.secretKeyVisible) {
        // Show the actual secret key
        secretKeyEl.textContent = state.currentInspectSecretKey;
        secretKeyEl.style.color = '';
        // Change icon to "eye-off"
        iconEl.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>';
    } else {
        // Show asterisks
        secretKeyEl.textContent = '••••••••••••••••••••••••••••••••';
        secretKeyEl.style.color = '';
        // Change icon to "eye"
        iconEl.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
    }
}

// Credential Selector for Buckets
async function loadBucketsCredentialSelector() {
    const selectEl = document.getElementById('bucket-credential-select');
    const infoEl = document.getElementById('selected-credential-info');
    const nameEl = document.getElementById('selected-credential-name');
    
    try {
        const response = await apiCall('/settings/credentials');
        const credentials = response.credentials || [];
        
        // Populate dropdown
        selectEl.innerHTML = '<option value="">-- Select a credential --</option>';
        credentials.forEach(cred => {
            const option = document.createElement('option');
            option.value = cred.access_key;
            option.textContent = `${cred.name} (${cred.access_key})`;
            option.dataset.name = cred.name;
            selectEl.appendChild(option);
        });
        
        // Restore previously selected credential from localStorage
        const savedCredential = localStorage.getItem('selected_s3_credential');
        if (savedCredential && credentials.some(c => c.access_key === savedCredential)) {
            selectEl.value = savedCredential;
            state.selectedCredential = savedCredential;
            updateSelectedCredentialInfo();
        }
        
        // Handle selection change
        selectEl.onchange = function() {
            const accessKey = this.value;
            if (accessKey) {
                state.selectedCredential = accessKey;
                localStorage.setItem('selected_s3_credential', accessKey);
                updateSelectedCredentialInfo();
                showToast('Credential selected for S3 operations', 'success');
            } else {
                state.selectedCredential = null;
                localStorage.removeItem('selected_s3_credential');
                infoEl.style.display = 'none';
                showToast('No credential selected - S3 operations will fail', 'warning');
            }
        };
        
    } catch (error) {
        console.error('Failed to load credentials for selector:', error);
        selectEl.innerHTML = '<option value="">Failed to load credentials</option>';
    }
    
    function updateSelectedCredentialInfo() {
        const selectEl = document.getElementById('bucket-credential-select');
        const selectedOption = selectEl.options[selectEl.selectedIndex];
        
        if (selectedOption && selectedOption.value) {
            const name = selectedOption.dataset.name;
            
            nameEl.textContent = name;
            infoEl.style.display = 'block';
        } else {
            infoEl.style.display = 'none';
        }
    }
}

// Bucket Management
async function loadBuckets() {
    const listEl = document.getElementById('buckets-list');
    listEl.innerHTML = '<div class="empty-state">Loading buckets...</div>';
    
    try {
        const response = await apiCall('/settings/buckets');
        const buckets = response.buckets || [];
        
        if (buckets.length === 0) {
            listEl.innerHTML = `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                    </svg>
                    <p>No buckets yet</p>
                    <p style="font-size: 0.875rem; margin-top: 0.5rem;">Create your first bucket to store data</p>
                </div>
            `;
        } else {
            listEl.innerHTML = buckets.map(bucket => `
                <div class="credential-card">
                    <div class="credential-info">
                        <h4>${bucket.name}</h4>
                        <div class="credential-meta">
                            <span>Created: ${new Date(bucket.created_at).toLocaleDateString()}</span>
                        </div>
                    </div>
                    <div class="credential-actions">
                        <button class="btn-icon" onclick="showUploadModal('${bucket.name}')" title="Upload">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="17 8 12 3 7 8"></polyline>
                                <line x1="12" y1="3" x2="12" y2="15"></line>
                            </svg>
                        </button>
                        <button class="btn-icon" onclick="inspectBucket('${bucket.name}')" title="Inspect">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                            </svg>
                        </button>
                        <button class="btn-icon btn-danger" onclick="deleteBucket('${bucket.name}')" title="Delete">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polyline points="3 6 5 6 21 6"></polyline>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                            </svg>
                        </button>
                    </div>
                </div>
            `).join('');
        }
    } catch (error) {
        listEl.innerHTML = `
            <div class="empty-state">
                <p style="color: var(--danger-color);">Failed to load buckets</p>
                <p style="font-size: 0.875rem; margin-top: 0.5rem;">${error.message}</p>
            </div>
        `;
    }
}

async function handleCreateBucket() {
    const name = document.getElementById('new-bucket-name').value;
    
    if (!name) {
        showToast('Please enter a bucket name', 'error');
        return;
    }
    
    // Validate bucket name (basic S3 naming rules)
    const bucketNameRegex = /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/;
    if (!bucketNameRegex.test(name) || name.length < 3 || name.length > 63) {
        showToast('Invalid bucket name. Must be 3-63 characters, lowercase, and start/end with letter or number', 'error');
        return;
    }
    
    try {
        await apiCall('/settings/buckets', {
            method: 'POST',
            body: JSON.stringify({ name })
        });
        
        hideModals();
        showToast('Bucket created successfully!', 'success');
        loadBuckets();
        
        // Clear form
        document.getElementById('new-bucket-name').value = '';
    } catch (error) {
        showToast('Failed to create bucket: ' + error.message, 'error');
    }
}

async function deleteBucket(name) {
    if (!confirm(`Are you sure you want to delete bucket "${name}"? The bucket must be empty.`)) {
        return;
    }
    
    try {
        await apiCall(`/settings/buckets/${name}`, { method: 'DELETE' });
        showToast('Bucket deleted', 'success');
        loadBuckets();
    } catch (error) {
        showToast('Failed to delete bucket: ' + error.message, 'error');
    }
}

// Bucket Inspection
async function inspectBucket(bucketName) {
    state.currentBucket = bucketName;
    state.currentPrefix = '';
    
    document.getElementById('inspect-bucket-title').textContent = `Bucket: ${bucketName}`;
    showModal('inspect-bucket-modal');
    
    await loadBucketObjects();
}

async function loadBucketObjects(prefix = '') {
    state.currentPrefix = prefix;
    const listEl = document.getElementById('bucket-objects-list');
    const breadcrumb = document.getElementById('bucket-breadcrumb');
    
    // Update breadcrumb
    if (!prefix) {
        breadcrumb.innerHTML = `<span style="color: var(--text-secondary);">/ (root)</span>`;
    } else {
        const parts = prefix.split('/').filter(p => p);
        let path = '';
        breadcrumb.innerHTML = `
            <a href="#" onclick="loadBucketObjects(''); return false;" style="color: var(--primary-color); text-decoration: none;">/</a>
            ${parts.map((part, idx) => {
                path += part + '/';
                const isLast = idx === parts.length - 1;
                if (isLast) {
                    return `<span style="color: var(--text-secondary);"> / ${part}</span>`;
                }
                return `<a href="#" onclick="loadBucketObjects('${path}'); return false;" style="color: var(--primary-color); text-decoration: none;"> / ${part}</a>`;
            }).join('')}
        `;
    }
    
    listEl.innerHTML = '<div class="empty-state">Loading objects...</div>';
    
    try {
        const response = await apiCall(`/s3/${state.currentBucket}${prefix ? '?prefix=' + prefix : ''}`);
        
        console.log('loadBucketObjects response:', response);
        
        // Parse JSON response from backend
        const objects = response.objects || [];
        
        // Separate folders and files
        const folders = [];
        const files = [];
        
        objects.forEach(obj => {
            if (obj.key.endsWith('/')) {
                // It's a folder
                folders.push(obj.key);
            } else {
                // It's a file
                files.push({
                    key: obj.key,
                    size: obj.size || 0,
                    modified: obj.last_modified || obj.lastModified || new Date().toISOString()
                });
            }
        });
        
        if (folders.length === 0 && files.length === 0) {
            listEl.innerHTML = `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                    </svg>
                    <p>No objects found</p>
                </div>
            `;
            return;
        }
        
        let html = '<div style="display: flex; flex-direction: column; gap: 0.5rem;">';
        
        // Show folders first
        folders.forEach(folder => {
            const folderName = folder.replace(prefix, '').replace('/', '');
            html += `
                <div class="credential-card" onclick="loadBucketObjects('${folder}')" style="cursor: pointer;">
                    <div class="credential-info">
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" style="color: var(--primary-color);">
                                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                            </svg>
                            <h4 style="margin: 0;">${folderName}/</h4>
                        </div>
                        <div class="credential-meta">
                            <span>Folder</span>
                        </div>
                    </div>
                </div>
            `;
        });
        
        // Show files
        files.forEach(file => {
            const fileName = file.key.replace(prefix, '');
            const fileSize = formatBytes(parseInt(file.size));
            const fileDate = new Date(file.modified).toLocaleString();
            
            html += `
                <div class="credential-card">
                    <div class="credential-info">
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" style="color: var(--text-secondary);">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                                <polyline points="14 2 14 8 20 8"></polyline>
                                <line x1="16" y1="13" x2="8" y2="13"></line>
                                <line x1="16" y1="17" x2="8" y2="17"></line>
                                <polyline points="10 9 9 9 8 9"></polyline>
                            </svg>
                            <h4 style="margin: 0;">${fileName}</h4>
                        </div>
                        <div class="credential-meta">
                            <span>${fileSize}</span> • <span>${fileDate}</span>
                        </div>
                    </div>
                    <div class="credential-actions">
                        <button class="btn-icon" onclick="downloadObject('${file.key}')" title="Download">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="7 10 12 15 17 10"></polyline>
                                <line x1="12" y1="15" x2="12" y2="3"></line>
                            </svg>
                        </button>
                        <button class="btn-icon btn-danger" onclick="deleteObject('${file.key}')" title="Delete">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polyline points="3 6 5 6 21 6"></polyline>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                            </svg>
                        </button>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        listEl.innerHTML = html;
        
    } catch (error) {
        listEl.innerHTML = `
            <div class="empty-state">
                <p style="color: var(--danger-color);">Failed to load objects</p>
                <p style="font-size: 0.875rem; margin-top: 0.5rem;">${error.message}</p>
            </div>
        `;
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

async function downloadObject(key) {
    try {
        window.location.href = `${CONFIG.gatewayUrl}/s3/${state.currentBucket}/${key}`;
        showToast('Download started', 'success');
    } catch (error) {
        showToast('Failed to download: ' + error.message, 'error');
    }
}

async function deleteObject(key) {
    const fileName = key.split('/').pop();
    
    if (!confirm(`Are you sure you want to delete "${fileName}"?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${CONFIG.gatewayUrl}/s3/${state.currentBucket}/${key}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Delete failed: ${response.statusText}`);
        }
        
        showToast(`Object "${fileName}" deleted successfully`, 'success');
        
        // Reload bucket contents to reflect the deletion
        await loadBucketObjects(state.currentPrefix || '');
    } catch (error) {
        console.error('Failed to delete object:', error);
        showToast('Failed to delete object: ' + error.message, 'error');
    }
}

function showUploadModal(bucketName) {
    state.currentBucket = bucketName;
    state.uploadPrefix = '';
    document.getElementById('upload-bucket-name').textContent = bucketName;
    document.getElementById('upload-file-input').value = '';
    document.getElementById('upload-key-prefix').value = '';
    showModal('upload-modal');
}

async function handleFileUpload() {
    const fileInput = document.getElementById('upload-file-input');
    const prefix = document.getElementById('upload-key-prefix').value;
    
    console.log('handleFileUpload called');
    console.log('Current bucket:', state.currentBucket);
    console.log('Current prefix:', state.currentPrefix);
    
    if (!fileInput.files || fileInput.files.length === 0) {
        showToast('Please select a file to upload', 'error');
        return;
    }
    
    const file = fileInput.files[0];
    const key = prefix ? `${prefix}/${file.name}` : file.name;
    
    console.log('Uploading file:', file.name);
    console.log('File size:', file.size);
    console.log('Key:', key);
    console.log('Upload URL:', `${CONFIG.gatewayUrl}/s3/${state.currentBucket}/${key}`);
    
    try {
        // Disable button during upload
        const uploadBtn = document.getElementById('confirm-upload');
        const originalText = uploadBtn.textContent;
        uploadBtn.disabled = true;
        uploadBtn.textContent = 'Uploading...';
        
        // Upload file directly as binary
        const headers = {
            'Authorization': `Bearer ${state.token}`,
            'Content-Type': file.type || 'application/octet-stream'
        };
        
        // Add credential header if a credential is selected
        if (state.selectedCredential) {
            headers['X-S3-Credential-AccessKey'] = state.selectedCredential;
        }
        
        const response = await fetch(`${CONFIG.gatewayUrl}/s3/${state.currentBucket}/${key}`, {
            method: 'PUT',
            headers: headers,
            body: file
        });
        
        console.log('Upload response status:', response.status);
        console.log('Upload response ok:', response.ok);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Upload failed with response:', errorText);
            throw new Error(`Upload failed: ${response.statusText}`);
        }
        
        console.log('Upload successful, closing upload modal');
        
        // Close only the upload modal, not all modals
        document.getElementById('upload-modal').style.display = 'none';
        document.getElementById('upload-modal').classList.remove('active');
        
        showToast(`File "${file.name}" uploaded successfully!`, 'success');
        
        console.log('Reloading bucket objects...');
        console.log('Will reload bucket:', state.currentBucket, 'with prefix:', state.currentPrefix);
        
        // Reload bucket contents to show the new file
        if (state.currentBucket) {
            await loadBucketObjects(state.currentPrefix || '');
            console.log('Bucket objects reloaded');
        } else {
            console.warn('No current bucket set, skipping reload');
        }
        
        // Reset button
        uploadBtn.disabled = false;
        uploadBtn.textContent = originalText;
        
    } catch (error) {
        console.error('Upload failed:', error);
        showToast('Failed to upload file: ' + error.message, 'error');
        
        // Reset button
        const uploadBtn = document.getElementById('confirm-upload');
        uploadBtn.disabled = false;
        uploadBtn.textContent = 'Upload';
    }
}

// S3 Browser (Legacy - keeping for compatibility)
async function handleListBucket() {
    const bucket = document.getElementById('bucket-name').value;
    if (!bucket) {
        showToast('Please enter a bucket name', 'error');
        return;
    }
    
    state.currentBucket = bucket;
    const listEl = document.getElementById('s3-objects-list');
    listEl.innerHTML = '<div class="empty-state">Loading objects...</div>';
    
    try {
        const response = await apiCall(`/s3/${bucket}${state.currentPrefix ? '?prefix=' + state.currentPrefix : ''}`);
        
        // Parse XML response (S3 returns XML)
        const parser = new DOMParser();
        const xml = parser.parseFromString(response, 'text/xml');
        const contents = xml.getElementsByTagName('Contents');
        
        if (contents.length === 0) {
            listEl.innerHTML = `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                    </svg>
                    <p>No objects found</p>
                </div>
            `;
        } else {
            const items = Array.from(contents).map(item => {
                const key = item.getElementsByTagName('Key')[0].textContent;
                const size = item.getElementsByTagName('Size')[0].textContent;
                const modified = item.getElementsByTagName('LastModified')[0].textContent;
                
                return { key, size, modified };
            });
            
            listEl.innerHTML = items.map(item => `
                <div class="object-item" onclick="selectObject('${item.key}')">
                    <div class="object-info">
                        <div class="object-icon">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                                <polyline points="13 2 13 9 20 9"></polyline>
                            </svg>
                        </div>
                        <div>
                            <div>${item.key}</div>
                            <div style="font-size: 0.875rem; color: var(--text-secondary);">
                                ${formatBytes(item.size)} • ${new Date(item.modified).toLocaleString()}
                            </div>
                        </div>
                    </div>
                    <button class="btn-icon" onclick="downloadObject(event, '${item.key}')" title="Download">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" y1="15" x2="12" y2="3"></line>
                        </svg>
                    </button>
                </div>
            `).join('');
        }
    } catch (error) {
        listEl.innerHTML = `
            <div class="empty-state">
                <p style="color: var(--danger-color);">Failed to list objects</p>
                <p style="font-size: 0.875rem; margin-top: 0.5rem;">${error.message}</p>
            </div>
        `;
    }
}

function selectObject(key) {
    console.log('Selected object:', key);
    // Could implement preview or details view
}

async function downloadObject(event, key) {
    event.stopPropagation();
    
    try {
        const response = await fetch(`${CONFIG.gatewayUrl}/s3/${state.currentBucket}/${key}`, {
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = key.split('/').pop();
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        showToast('Download started', 'success');
    } catch (error) {
        showToast('Failed to download: ' + error.message, 'error');
    }
}

function handleUpload() {
    const input = document.createElement('input');
    input.type = 'file';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        if (!state.currentBucket) {
            showToast('Please select a bucket first', 'error');
            return;
        }
        
        try {
            const formData = new FormData();
            formData.append('file', file);
            
            await fetch(`${CONFIG.gatewayUrl}/s3/${state.currentBucket}/${file.name}`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${state.token}`
                },
                body: file
            });
            
            showToast('Upload successful!', 'success');
            handleListBucket();
        } catch (error) {
            showToast('Upload failed: ' + error.message, 'error');
        }
    };
    input.click();
}

// Policies
// Policies Management
async function loadPolicies() {
    const listEl = document.getElementById('policies-list');
    listEl.innerHTML = '<div class="empty-state">Loading policies...</div>';
    
    try {
        const response = await apiCall('/settings/policies');
        let policies = response.policies || [];
        
        // Use simulated admin status for filtering
        const isAdmin = state.actualIsAdmin && state.simulatedIsAdmin;
        
        // Filter policies based on user role
        // Admin sees all policies, regular users see only their assigned policies
        if (!isAdmin && state.userRoles) {
            policies = policies.filter(policy => state.userRoles.includes(policy.name));
        }
        
        state.policies = policies;
        
        if (policies.length === 0) {
            listEl.innerHTML = `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                    </svg>
                    <p>No policies configured</p>
                    <p style="font-size: 0.875rem; margin-top: 0.5rem;">Create your first policy to get started</p>
                </div>
            `;
        } else {
            listEl.innerHTML = policies.map(policy => `
                <div class="credential-card">
                    <div class="credential-info">
                        <h4>${policy.name}</h4>
                        <div class="credential-meta">${policy.description || 'No description'}</div>
                    </div>
                    <div class="credential-actions">
                        <button class="btn-icon" onclick="viewPolicy('${policy.name}')" title="View">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                        </button>
                        <button class="btn-icon admin-only" onclick="editPolicy('${policy.name}')" title="Edit" style="display: ${isAdmin ? '' : 'none'};">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                            </svg>
                        </button>
                        <button class="btn-icon btn-danger admin-only" onclick="deletePolicy('${policy.name}')" title="Delete" style="display: ${isAdmin ? '' : 'none'};">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polyline points="3 6 5 6 21 6"></polyline>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                            </svg>
                        </button>
                    </div>
                </div>
            `).join('');
        }
    } catch (error) {
        listEl.innerHTML = `<div class="empty-state">Failed to load policies: ${error.message}</div>`;
    }
}

function showCreatePolicyModal() {
    const modal = document.getElementById('policy-modal');
    document.getElementById('policy-modal-title').textContent = 'Create New Policy';
    document.getElementById('policy-name').value = '';
    document.getElementById('policy-name').disabled = false;
    document.getElementById('policy-description').value = '';
    document.getElementById('policy-json').value = JSON.stringify({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::*"]
            }
        ]
    }, null, 2);
    document.getElementById('policy-json').disabled = false;
    document.getElementById('policy-validation').innerHTML = '';
    document.getElementById('confirm-save-policy').disabled = true;
    document.getElementById('confirm-save-policy').style.display = 'inline-block';
    
    state.editingPolicy = null;
    state.policyValidated = false;
    modal.style.display = 'flex';
}

async function viewPolicy(name) {
    try {
        const response = await apiCall(`/settings/policies/${name}`);
        const policy = response.policy;
        
        document.getElementById('policy-modal-title').textContent = `View Policy: ${name}`;
        document.getElementById('policy-name').value = policy.name;
        document.getElementById('policy-name').disabled = true;
        document.getElementById('policy-description').value = policy.description || '';
        document.getElementById('policy-json').value = JSON.stringify(policy.policy, null, 2);
        document.getElementById('policy-json').disabled = true;
        document.getElementById('confirm-save-policy').style.display = 'none';
        document.getElementById('policy-validation').innerHTML = '';
        
        document.getElementById('policy-modal').style.display = 'flex';
    } catch (error) {
        showToast('Failed to load policy: ' + error.message, 'error');
    }
}

async function editPolicy(name) {
    try {
        const response = await apiCall(`/settings/policies/${name}`);
        const policy = response.policy;
        
        document.getElementById('policy-modal-title').textContent = `Edit Policy: ${name}`;
        document.getElementById('policy-name').value = policy.name;
        document.getElementById('policy-name').disabled = true;
        document.getElementById('policy-description').value = policy.description || '';
        document.getElementById('policy-json').value = JSON.stringify(policy.policy, null, 2);
        document.getElementById('policy-json').disabled = false;
        document.getElementById('confirm-save-policy').disabled = true;
        document.getElementById('confirm-save-policy').style.display = 'inline-block';
        document.getElementById('policy-validation').innerHTML = '';
        
        state.editingPolicy = name;
        state.policyValidated = false;
        document.getElementById('policy-modal').style.display = 'flex';
    } catch (error) {
        showToast('Failed to load policy: ' + error.message, 'error');
    }
}

async function savePolicy() {
    const name = document.getElementById('policy-name').value.trim();
    const description = document.getElementById('policy-description').value.trim();
    const jsonText = document.getElementById('policy-json').value.trim();
    
    if (!name) {
        showToast('Please enter a policy name', 'error');
        return;
    }
    
    // Validate policy name format: only alphanumeric, dash, and underscore
    const policyNameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!policyNameRegex.test(name)) {
        showToast('Policy name can only contain letters, numbers, dashes (-), and underscores (_)', 'error');
        return;
    }
    
    let policyJSON;
    try {
        policyJSON = JSON.parse(jsonText);
    } catch (error) {
        showToast('Invalid JSON: ' + error.message, 'error');
        return;
    }
    
    try {
        const isEdit = state.editingPolicy !== null;
        const method = isEdit ? 'PUT' : 'POST';
        const endpoint = isEdit ? `/settings/policies/${name}` : '/settings/policies';
        
        await apiCall(endpoint, {
            method,
            body: JSON.stringify({
                name,
                description,
                policy: policyJSON
            })
        });
        
        hideModals();
        showToast(`Policy ${isEdit ? 'updated' : 'created'} successfully!`, 'success');
        loadPolicies();
    } catch (error) {
        showToast('Failed to save policy: ' + error.message, 'error');
    }
}

async function deletePolicy(name) {
    if (!confirm(`Are you sure you want to delete policy "${name}"?`)) {
        return;
    }
    
    try {
        await apiCall(`/settings/policies/${name}`, { method: 'DELETE' });
        showToast('Policy deleted successfully', 'success');
        loadPolicies();
    } catch (error) {
        showToast('Failed to delete policy: ' + error.message, 'error');
    }
}

async function validatePolicyJSON() {
    const jsonText = document.getElementById('policy-json').value.trim();
    const validationEl = document.getElementById('policy-validation');
    const saveBtn = document.getElementById('confirm-save-policy');
    
    let policyJSON;
    try {
        policyJSON = JSON.parse(jsonText);
    } catch (error) {
        validationEl.innerHTML = `<span style="color: #ef4444;">❌ Invalid JSON: ${error.message}</span>`;
        saveBtn.disabled = true;
        state.policyValidated = false;
        return;
    }
    
    try {
        const response = await apiCall('/settings/policies/validate', {
            method: 'POST',
            body: JSON.stringify({
                name: 'temp',
                policy: policyJSON
            })
        });
        
        if (response.valid) {
            validationEl.innerHTML = `<span style="color: #10b981;">✓ Policy is valid - you can now save</span>`;
            saveBtn.disabled = false;
            state.policyValidated = true;
        } else {
            validationEl.innerHTML = `<span style="color: #ef4444;">❌ ${response.error}</span>`;
            saveBtn.disabled = true;
            state.policyValidated = false;
        }
    } catch (error) {
        validationEl.innerHTML = `<span style="color: #ef4444;">❌ Validation failed: ${error.message}</span>`;
        saveBtn.disabled = true;
        state.policyValidated = false;
    }
}

// ===== ROLE MANAGEMENT =====

async function loadRoles() {
    try {
        const response = await apiCall('/settings/roles');
        const roles = response.roles || [];
        
        const rolesList = document.getElementById('roles-list');
        
        if (roles.length === 0) {
            rolesList.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 2rem;">No roles configured yet. Create one to map OIDC roles to policies.</p>';
            return;
        }
        
        rolesList.innerHTML = roles.map(role => `
            <div class="credential-card">
                <div class="credential-info">
                    <h4>${escapeHtml(role.name)} ${getBackendStatusBadge(role.backend_status)}</h4>
                    <div class="credential-meta">
                        ${escapeHtml(role.description || 'No description')}
                    </div>
                    <div class="credential-meta" style="margin-top: 0.5rem;">
                        <strong>Policies:</strong>
                        ${role.policies && role.policies.length > 0 
                            ? role.policies.map(p => `<span class="policy-badge">${escapeHtml(p)}</span>`).join(' ')
                            : '<em>No policies assigned</em>'}
                    </div>
                </div>
                <div class="credential-actions">
                    <button class="btn-icon admin-only" onclick="editRole('${escapeHtml(role.name)}')" title="Edit Role">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                        </svg>
                    </button>
                    <button class="btn-icon btn-danger admin-only" onclick="deleteRole('${escapeHtml(role.name)}')" title="Delete Role">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <polyline points="3 6 5 6 21 6"></polyline>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                        </svg>
                    </button>
                </div>
            </div>
        `).join('');
        
        updateUIForAdminMode();
    } catch (error) {
        document.getElementById('roles-list').innerHTML = 
            '<p style="text-align: center; color: var(--error-color); padding: 2rem;">Failed to load roles</p>';
        showToast('Failed to load roles: ' + error.message, 'error');
    }
}

// getBackendStatusBadge returns a status badge for backend sync status
function getBackendStatusBadge(status) {
    if (!status) return '';
    
    const statusConfig = {
        'OK': { text: '✓ Synced', class: 'status-ok' },
        'Missing': { text: '⚠ Missing', class: 'status-warning' },
        'PolicyMismatch': { text: '⚠ Policy Mismatch', class: 'status-warning' },
        'Error': { text: '✗ Error', class: 'status-error' },
        'Unknown': { text: '? Unknown', class: 'status-unknown' }
    };
    
    const config = statusConfig[status] || statusConfig['Unknown'];
    return `<span class="status-badge ${config.class}" title="Backend status: ${status}">${config.text}</span>`;
}

async function showCreateRoleModal() {
    const modal = document.getElementById('role-modal');
    document.getElementById('role-modal-title').textContent = 'Create New Role';
    document.getElementById('role-name').value = '';
    document.getElementById('role-name').disabled = false;
    document.getElementById('role-description').value = '';
    
    state.editingRole = null;
    
    // Load available policies for selection
    await loadPoliciesForRoleModal();
    
    modal.style.display = 'flex';
}

async function editRole(name) {
    try {
        const response = await apiCall(`/settings/roles/${name}`);
        const role = response.role;
        
        document.getElementById('role-modal-title').textContent = `Edit Role: ${name}`;
        document.getElementById('role-name').value = role.name;
        document.getElementById('role-name').disabled = true;
        document.getElementById('role-description').value = role.description || '';
        
        state.editingRole = name;
        state.roleSelectedPolicies = role.policies || [];
        
        // Load available policies and pre-select assigned ones
        await loadPoliciesForRoleModal();
        
        document.getElementById('role-modal').style.display = 'flex';
    } catch (error) {
        showToast('Failed to load role: ' + error.message, 'error');
    }
}

async function loadPoliciesForRoleModal() {
    try {
        const response = await apiCall('/settings/policies');
        const policies = response.policies || [];
        
        const selectedPolicies = state.roleSelectedPolicies || [];
        
        const selector = document.getElementById('role-policies-selector');
        
        if (policies.length === 0) {
            selector.innerHTML = '<p style="color: var(--text-secondary); font-size: 0.875rem;">No policies available. Create policies first.</p>';
            return;
        }
        
        selector.innerHTML = policies.map(policy => {
            const isSelected = selectedPolicies.includes(policy.name);
            return `
                <label style="display: flex; align-items: center; padding: 0.25rem 0; cursor: pointer; border-radius: 4px; transition: background 0.2s;" 
                       onmouseover="this.style.background='var(--hover-bg)'" 
                       onmouseout="this.style.background='transparent'">
                    <input type="checkbox" 
                           value="${escapeHtml(policy.name)}" 
                           ${isSelected ? 'checked' : ''}
                           onchange="toggleRolePolicy('${escapeHtml(policy.name)}', this.checked)"
                           style="flex: 0 0 10%; margin: 0;">
                    <div style="flex: 1; padding-left: 0.5rem;">
                        <strong>${escapeHtml(policy.name)}</strong>
                        ${policy.description ? `<span style="color: var(--text-secondary); font-size: 0.75rem; margin-left: 0.5rem;">— ${escapeHtml(policy.description)}</span>` : ''}
                    </div>
                </label>
            `;
        }).join('');
    } catch (error) {
        console.error('Failed to load policies for role modal:', error);
        document.getElementById('role-policies-selector').innerHTML = 
            `<p style="color: var(--danger-color); font-size: 0.875rem;">Failed to load policies: ${error.message}</p>`;
    }
}

function toggleRolePolicy(policyName, isChecked) {
    if (!state.roleSelectedPolicies) {
        state.roleSelectedPolicies = [];
    }
    
    if (isChecked) {
        if (!state.roleSelectedPolicies.includes(policyName)) {
            state.roleSelectedPolicies.push(policyName);
        }
    } else {
        state.roleSelectedPolicies = state.roleSelectedPolicies.filter(p => p !== policyName);
    }
}

async function saveRole() {
    const name = document.getElementById('role-name').value.trim();
    const description = document.getElementById('role-description').value.trim();
    const policies = state.roleSelectedPolicies || [];
    
    if (!name) {
        showToast('Please enter a role name', 'error');
        return;
    }
    
    // Validate role name format: only alphanumeric, dash, and underscore
    const roleNameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!roleNameRegex.test(name)) {
        showToast('Role name can only contain letters, numbers, dashes (-), and underscores (_)', 'error');
        return;
    }
    
    if (policies.length === 0) {
        if (!confirm('This role has no policies assigned. Users with this role will have no permissions. Continue?')) {
            return;
        }
    }
    
    try {
        const isEdit = state.editingRole !== null;
        const method = isEdit ? 'PUT' : 'POST';
        const endpoint = isEdit ? `/settings/roles/${name}` : '/settings/roles';
        
        await apiCall(endpoint, {
            method,
            body: JSON.stringify({
                name,
                description,
                policies
            })
        });
        
        hideModals();
        showToast(`Role ${isEdit ? 'updated' : 'created'} successfully!`, 'success');
        loadRoles();
        
        // Update all credentials affected by this role change
        try {
            const updateResponse = await apiCall('/settings/credentials/update-all', { method: 'POST' });
            if (updateResponse.updated_count > 0) {
                let message = `Updated ${updateResponse.updated_count} credential(s)`;
                if (updateResponse.roles_updated_count > 0) {
                    message += ` and cleaned up roles for ${updateResponse.roles_updated_count} credential(s)`;
                }
                showToast(message, 'success');
            } else if (updateResponse.total_count > 0) {
                showToast(`No credentials needed updating`, 'info');
            }
        } catch (updateError) {
            showToast('Role saved but failed to update credentials: ' + updateError.message, 'warning');
        }
        
        // Reset state
        state.roleSelectedPolicies = [];
    } catch (error) {
        showToast('Failed to save role: ' + error.message, 'error');
    }
}

async function deleteRole(name) {
    if (!confirm(`Are you sure you want to delete role "${name}"?\n\nUsers with this role will lose their policy mappings.`)) {
        return;
    }
    
    try {
        await apiCall(`/settings/roles/${name}`, { method: 'DELETE' });
        showToast('Role deleted successfully', 'success');
        loadRoles();
    } catch (error) {
        showToast('Failed to delete role: ' + error.message, 'error');
    }
}

// Expose policy functions to global scope
window.viewPolicy = viewPolicy;
window.editPolicy = editPolicy;
window.deletePolicy = deletePolicy;
window.showCreatePolicyModal = showCreatePolicyModal;
window.validatePolicyJSON = validatePolicyJSON;

// Settings
async function loadSettings() {
    checkGatewayHealth();
}

// UI Helpers
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    modal.style.display = 'flex';
    modal.classList.add('active');
}

function hideModals() {
    document.querySelectorAll('.modal').forEach(modal => {
        modal.style.display = 'none';
        modal.classList.remove('active');
    });
    // Re-enable form fields that might have been disabled for view mode
    document.getElementById('policy-json').disabled = false;
    document.getElementById('confirm-save-policy').style.display = 'inline-block';
}

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast show ${type}`;
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

// User Management (Admin Only)
async function loadUsers() {
    const listEl = document.getElementById('users-list');
    listEl.innerHTML = '<div class="empty-state">Loading users...</div>';
    
    try {
        const response = await apiCall('/settings/users');
        const users = response.users || [];
        
        if (users.length === 0) {
            listEl.innerHTML = `
                <div class="empty-state">
                    <p>No users found</p>
                </div>
            `;
            return;
        }
        
        listEl.innerHTML = users.map(username => `
            <div class="credential-card">
                <div class="credential-info">
                    <h4>${username}</h4>
                </div>
                <div class="credential-actions">
                    <button class="btn-icon btn-danger" onclick="deleteUser('${username}')" title="Delete User">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <polyline points="3 6 5 6 21 6"></polyline>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                        </svg>
                    </button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        listEl.innerHTML = `
            <div class="empty-state">
                <p style="color: var(--danger-color);">Failed to load users</p>
                <p style="font-size: 0.875rem; margin-top: 0.5rem;">${error.message}</p>
            </div>
        `;
    }
}

async function deleteUser(username) {
    if (!confirm(`Are you sure you want to delete user "${username}"?\n\nThis will:\n- Delete the IAM user\n- Delete all access keys\n- Remove all policies\n\nThis action cannot be undone.`)) {
        return;
    }
    
    try {
        await apiCall(`/settings/users/${encodeURIComponent(username)}`, {
            method: 'DELETE'
        });
        showToast('User deleted successfully', 'success');
        loadUsers(); // Reload user list
    } catch (error) {
        showToast('Failed to delete user: ' + error.message, 'error');
    }
}

// Expose functions to global scope for inline event handlers
window.copyCredential = copyCredential;
window.deleteCredential = deleteCredential;
window.selectObject = selectObject;
window.downloadObject = downloadObject;
