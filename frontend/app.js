// S3 Access Manager - Frontend Application
// Configuration
const CONFIG = {
    gatewayUrl: '',  // Empty string since frontend and API are on same origin
    oidcStorage: 'oidc_config',
    tokenStorage: 'auth_token',
    userStorage: 'user_info',
    tenant: null     // Will be set from URL path
};

// State Management
const state = {
    token: null,
    userInfo: null,
    credentials: [],
    selectedCredential: null,  // Selected credential for S3 operations
    actualIsAdmin: false,      // Admin status from backend
    isGlobalAdmin: false,      // Global admin status from backend
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

// Extract tenant from URL path
function getTenantFromPath() {
    const path = window.location.pathname;
    const match = path.match(/^\/tenant\/([^\/]+)/);
    return match ? match[1] : null;
}

// Load OIDC configuration from backend
async function loadOIDCConfig() {
    try {
        let endpoint = '/oidc-config';
        if (CONFIG.tenant) {
            endpoint = `/tenant/${CONFIG.tenant}/oidc-config`;
        }
        
        const response = await fetch(`${CONFIG.gatewayUrl}${endpoint}`);
        if (!response.ok) {
            throw new Error('Failed to load OIDC configuration');
        }
        const config = await response.json();
        
        // Set the form values
        document.getElementById('oidc-issuer').value = config.issuer || '';
        document.getElementById('client-id').value = config.client_id || '';
        
        console.log('OIDC config loaded:', config);
    } catch (error) {
        console.error('Failed to load OIDC config:', error);
        showToast('Failed to load OIDC configuration', 'error');
    }
}

// Initialize App
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

function initializeApp() {
    // Extract tenant from URL
    CONFIG.tenant = getTenantFromPath();
    
    // Load OIDC configuration if on login screen
    if (document.getElementById('login-screen').classList.contains('active')) {
        loadOIDCConfig();
    }
    
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
        state.actualIsAdmin = localStorage.getItem('is_admin') === 'true';
        state.isGlobalAdmin = localStorage.getItem('is_global_admin') === 'true';
        
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
    console.log('validateTokenAndShowDashboard called, tenant:', CONFIG.tenant);
    
    // If no tenant context, we can't validate via credentials endpoint
    // For non-global admins, show tenant selection directly
    if (!CONFIG.tenant) {
        console.log('No tenant context, checking if global admin...');
        // Try to determine if user is global admin by checking a root-level endpoint
        try {
            // Use apiCall which adds auth headers
            const data = await apiCall('/tenants', { method: 'GET' });
            console.log('Tenants response:', data);
            
            // Check if user is a global admin from the response
            state.isGlobalAdmin = data.is_global_admin || false;
            state.actualIsAdmin = state.isGlobalAdmin;
            localStorage.setItem('is_global_admin', state.isGlobalAdmin ? 'true' : 'false');
            console.log('Set isGlobalAdmin to', state.isGlobalAdmin, ', calling showDashboard');
            showDashboard(); // This will show tenant selection for non-global admins, or dashboard for global admins
            return;
        } catch (error) {
            console.error('Failed to check tenant access:', error);
        }
        
        // If tenant access check fails, show tenant selection anyway
        console.log('Tenant access check failed, showing tenant selection screen');
        showTenantSelectionScreen();
        return;
    }
    
    // We're in a tenant context, validate via credentials endpoint
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
        state.isGlobalAdmin = response.is_global_admin || false;
        state.userGroups = response.user_groups || [];
        
        // Store admin status
        localStorage.setItem('is_admin', state.actualIsAdmin.toString());
        localStorage.setItem('is_global_admin', state.isGlobalAdmin.toString());
        
        // Remember this tenant as the last visited one
        if (CONFIG.tenant) {
            localStorage.setItem('last_tenant', CONFIG.tenant);
        }
        
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
        
        // Get stored redirect URI
        const redirectUri = sessionStorage.getItem('redirect_uri');
        console.log('Redirect URI:', redirectUri);
        if (!redirectUri) {
            throw new Error('Redirect URI not found');
        }
        
        // Exchange authorization code for tokens via backend
        let endpoint = '/oidc/token';
        if (CONFIG.tenant) {
            endpoint = `/tenant/${CONFIG.tenant}/oidc/token`;
        }
        
        const tokenResponse = await fetch(`${CONFIG.gatewayUrl}${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                code: code,
                code_verifier: codeVerifier,
                redirect_uri: redirectUri
            })
        });
        
        if (!tokenResponse.ok) {
            const errorData = await tokenResponse.json().catch(() => ({}));
            throw new Error(errorData.error || 'Token exchange failed');
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
        
        console.log('Tokens stored, checking tenant context...');
        
        // Get authoritative user info from backend only if we're in a tenant context
        // Without tenant context, /settings/credentials will fail for non-global admins
        if (CONFIG.tenant) {
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
        } else {
            console.log('No tenant context, skipping credentials endpoint call');
        }
        
        // Clean up
        sessionStorage.removeItem('pkce_verifier');
        sessionStorage.removeItem('oauth_state');
        sessionStorage.removeItem('redirect_uri');
        window.history.replaceState({}, document.title, window.location.pathname);
        
        // Setup event listeners
        setupEventListeners();
        
        // Determine where to redirect after authentication
        await determinePostAuthDestination();
        
        // Show welcome message with username
        const username = state.userInfo.name || state.userInfo.email || state.userInfo.sub || 'User';
        showToast(`Welcome ${username}!`, 'success');
        
    } catch (error) {
        console.error('OIDC callback error:', error);
        showToast('Authentication failed: ' + error.message, 'error');
        
        // Clean up and show login
        sessionStorage.removeItem('pkce_verifier');
        sessionStorage.removeItem('oauth_state');
        sessionStorage.removeItem('redirect_uri');
        window.history.replaceState({}, document.title, window.location.pathname);
        showLoginScreen();
        setupEventListeners();
    }
}

async function determinePostAuthDestination() {
    try {
        console.log('Determining post-authentication destination...');
        
        // Get list of accessible tenants
        const tenantData = await apiCall('/tenants');
        const tenants = tenantData.tenants || [];
        const isGlobalAdmin = tenantData.is_global_admin || false;
        
        console.log('Tenant data:', { tenants: tenants.length, isGlobalAdmin });
        
        // Store global admin status
        state.isGlobalAdmin = isGlobalAdmin;
        localStorage.setItem('is_global_admin', isGlobalAdmin ? 'true' : 'false');
        
        // Check if user has a last visited tenant stored
        const lastTenant = localStorage.getItem('last_tenant');
        
        if (tenants.length === 0) {
            // No tenants accessible
            showToast('No tenants available. Please contact your administrator.', 'error');
            showLoginScreen();
            return;
        }
        
        if (tenants.length === 1) {
            // Only one tenant - redirect there directly
            const tenantName = tenants[0].name;
            console.log('Only one tenant available, redirecting to:', tenantName);
            localStorage.setItem('last_tenant', tenantName);
            window.location.href = `/tenant/${tenantName}/`;
            return;
        }
        
        // Multiple tenants available
        if (lastTenant && tenants.some(t => t.name === lastTenant)) {
            // Last tenant is still accessible - redirect there
            console.log('Redirecting to last tenant:', lastTenant);
            window.location.href = `/tenant/${lastTenant}/`;
            return;
        }
        
        // No valid last tenant or first time - show tenant selection
        console.log('Multiple tenants available, showing selection screen');
        showTenantSelectionScreen();
        
    } catch (error) {
        console.error('Failed to determine post-auth destination:', error);
        showToast('Failed to load tenant information', 'error');
        showLoginScreen();
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
    
    // Tenant name badge - click to switch tenant
    const tenantNameBadge = document.getElementById('tenant-name');
    if (tenantNameBadge) {
        tenantNameBadge.addEventListener('click', handleSwitchTenant);
    }
    
    // Admin mode toggle
    const adminToggle = document.getElementById('admin-mode-toggle');
    // Admin toggle removed - admin status is now determined by backend
    
    // Secret key visibility toggle
    const toggleSecretBtn = document.getElementById('toggle-secret-visibility');
    if (toggleSecretBtn) {
        toggleSecretBtn.addEventListener('click', toggleSecretKeyVisibility);
    }
    
    // Tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });
    
    // Credentials - only set up if elements exist (dashboard screen)
    const createCredentialBtn = document.getElementById('create-credential-btn');
    if (createCredentialBtn) {
        createCredentialBtn.addEventListener('click', async () => {
            showModal('create-credential-modal');
            await loadAvailableRolesForCredential();
        });
    }
    
    const updateCredentialsBtn = document.getElementById('update-credentials-btn');
    if (updateCredentialsBtn) {
        updateCredentialsBtn.addEventListener('click', updateAllCredentials);
    }
    
    const confirmCreateCredentialBtn = document.getElementById('confirm-create-credential');
    if (confirmCreateCredentialBtn) {
        confirmCreateCredentialBtn.addEventListener('click', handleCreateCredential);
    }
    
    const confirmSavePolicyBtn = document.getElementById('confirm-save-policy');
    if (confirmSavePolicyBtn) {
        confirmSavePolicyBtn.addEventListener('click', savePolicy);
    }
    
    const confirmSaveGroupBtn = document.getElementById('confirm-save-group');
    if (confirmSaveGroupBtn) {
        confirmSaveGroupBtn.addEventListener('click', saveRole);
    }
    
    // Modal close buttons
    document.querySelectorAll('.modal-close, .modal-cancel').forEach(btn => {
        btn.addEventListener('click', () => hideModals());
    });
    
    // Policy JSON change listener - invalidate validation when content changes
    const policyJsonEl = document.getElementById('policy-json');
    if (policyJsonEl) {
        policyJsonEl.addEventListener('input', () => {
            if (state.policyValidated) {
                const confirmBtn = document.getElementById('confirm-save-policy');
                const validationEl = document.getElementById('policy-validation');
                if (confirmBtn) confirmBtn.disabled = true;
                if (validationEl) {
                    validationEl.innerHTML = '<span style="color: #f59e0b;">⚠ Content changed - please validate again</span>';
                }
                state.policyValidated = false;
            }
        });
    }
}

// Screen Management
function showLoginScreen() {
    document.getElementById('login-screen').classList.add('active');
    document.getElementById('dashboard-screen').classList.remove('active');
    document.getElementById('tenant-selection-screen').classList.remove('active');
    
    // Fetch OIDC configuration from backend
    fetchOIDCConfiguration();
}

function showTenantSelectionScreen() {
    console.log('showTenantSelectionScreen called, isGlobalAdmin:', state.isGlobalAdmin);
    document.getElementById('login-screen').classList.remove('active');
    document.getElementById('dashboard-screen').classList.remove('active');
    document.getElementById('tenant-selection-screen').classList.add('active');
    
    // Show create tenant button only for global admins
    const createTenantBtn = document.getElementById('create-tenant-btn');
    if (createTenantBtn) {
        createTenantBtn.style.display = state.isGlobalAdmin ? 'inline-block' : 'none';
    }
    
    // Update title based on user type
    const titleEl = document.querySelector('#tenant-selection-screen h1');
    if (titleEl) {
        if (state.isGlobalAdmin) {
            titleEl.textContent = 'Manage Tenants';
        } else {
            titleEl.textContent = 'Select Tenant';
        }
    }
    
    // Load available tenants
    console.log('About to call loadTenantsForSelection()');
    loadTenantsForSelection();
}

async function loadTenantsForSelection() {
    console.log('loadTenantsForSelection called');
    try {
        console.log('Fetching tenants from /tenants endpoint...');
        const data = await apiCall('/tenants', {
            method: 'GET'
        });
        console.log('Tenants data received:', data);
        
        const tenantList = document.getElementById('tenant-list');
        tenantList.innerHTML = '';
        
        data.tenants.forEach(tenant => {
            const tenantCard = document.createElement('div');
            tenantCard.className = 'tenant-card';
            
            // For global admins on tenant selection screen, add management buttons
            if (state.isGlobalAdmin && !CONFIG.tenant) {
                tenantCard.innerHTML = `
                    <div class="tenant-info">
                        <h3>${tenant.name}</h3>
                        <p>${tenant.description || 'Manage S3 access for this tenant'}</p>
                    </div>
                    <div class="tenant-actions" style="display: flex; gap: 0.5rem;">
                        <button class="btn-icon" onclick="selectTenant('${tenant.name}'); event.stopPropagation();" title="Manage Tenant">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M9 18l6-6-6-6"/>
                            </svg>
                        </button>
                        <button class="btn-icon" onclick="inspectTenant('${tenant.name}'); event.stopPropagation();" title="View Details">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                        </button>
                        <button class="btn-icon" onclick="editTenant('${tenant.name}'); event.stopPropagation();" title="Edit">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                            </svg>
                        </button>
                        <button class="btn-icon" onclick="refreshTenantSRAM('${tenant.name}'); event.stopPropagation();" title="Refresh SRAM Status">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polyline points="23 4 23 10 17 10"></polyline>
                                <polyline points="1 20 1 14 7 14"></polyline>
                                <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"></path>
                            </svg>
                        </button>
                        <button class="btn-icon btn-danger" onclick="deleteTenant('${tenant.name}'); event.stopPropagation();" title="Delete">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polyline points="3 6 5 6 21 6"></polyline>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                            </svg>
                        </button>
                    </div>
                `;
            } else {
                // For regular users, simple click-to-select
                tenantCard.onclick = () => selectTenant(tenant.name);
                tenantCard.innerHTML = `
                    <div class="tenant-info">
                        <h3>${tenant.name}</h3>
                        <p>${tenant.description || 'Manage S3 access for this tenant'}</p>
                    </div>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M9 18l6-6-6-6"/>
                    </svg>
                `;
            }
            
            tenantList.appendChild(tenantCard);
        });
    } catch (error) {
        console.error('Failed to load tenants:', error);
        showToast('Failed to load tenants', 'error');
    }
}

function selectTenant(tenantName) {
    // Remember this tenant as the last visited one
    localStorage.setItem('last_tenant', tenantName);
    // Redirect to the selected tenant
    window.location.href = `/tenant/${tenantName}/`;
}

async function refreshTenantSRAM(tenantName) {
    try {
        showToast('Refreshing SRAM status...', 'info');
        
        const response = await fetch(`${CONFIG.gatewayUrl}/tenants/${tenantName}/sram-refresh`, {
            method: 'POST',
            headers: getAuthHeaders()
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to refresh SRAM status');
        }

        const data = await response.json();
        
        if (data.admin_accepted) {
            showToast(`✅ SRAM status refreshed: Admin invitation accepted`, 'success');
        } else {
            showToast(`🔄 SRAM status refreshed: No admin accepted yet`, 'info');
        }
        
        // Optionally refresh the tenant list to update any visual indicators
        await loadTenants();
        
    } catch (error) {
        console.error('Failed to refresh tenant SRAM status:', error);
        showToast('Failed to refresh SRAM status: ' + error.message, 'error');
    }
}

// Tenant switcher functions
let availableTenants = [];

async function loadAvailableTenants() {
    try {
        const data = await apiCall('/tenants', { method: 'GET', skipTenantPrefix: true });
        availableTenants = data.tenants || [];
        
        // Update tenant switcher visibility
        const switcher = document.getElementById('tenant-switcher');
        if (CONFIG.tenant && availableTenants.length > 1 && !state.isGlobalAdmin) {
            // Show switcher only for non-global admins with multiple tenants
            switcher.style.display = 'block';
        } else if (CONFIG.tenant) {
            // Just show tenant name without dropdown for single tenant or global admins
            switcher.style.display = 'block';
            const badge = document.getElementById('tenant-name');
            badge.onclick = null;
            badge.style.cursor = availableTenants.length > 1 ? 'pointer' : 'default';
        }
        
        return availableTenants;
    } catch (error) {
        console.error('Failed to load available tenants:', error);
        return [];
    }
}

function toggleTenantDropdown() {
    if (availableTenants.length <= 1) return; // Don't show dropdown for single tenant
    
    const dropdown = document.getElementById('tenant-dropdown');
    const isVisible = dropdown.style.display === 'block';
    
    if (isVisible) {
        dropdown.style.display = 'none';
    } else {
        // Populate dropdown with available tenants
        dropdown.innerHTML = availableTenants.map(tenant => {
            const isActive = tenant.name === CONFIG.tenant;
            return `
                <div class="tenant-dropdown-item ${isActive ? 'active' : ''}" onclick="switchToTenant('${tenant.name}')">
                    <span>${tenant.name}</span>
                    ${isActive ? '<span>✓</span>' : ''}
                </div>
            `;
        }).join('');
        
        dropdown.style.display = 'block';
    }
}

function switchToTenant(tenantName) {
    if (tenantName === CONFIG.tenant) {
        // Already on this tenant, just close dropdown
        document.getElementById('tenant-dropdown').style.display = 'none';
        return;
    }
    
    // Redirect to the selected tenant
    window.location.href = `/tenant/${tenantName}/`;
}

// Close dropdown when clicking outside
document.addEventListener('click', (event) => {
    const switcher = document.getElementById('tenant-switcher');
    const dropdown = document.getElementById('tenant-dropdown');
    
    if (switcher && dropdown && !switcher.contains(event.target)) {
        dropdown.style.display = 'none';
    }
});

function showCreateTenantForm() {
    document.getElementById('create-tenant-form').style.display = 'block';
    document.getElementById('create-tenant-btn').style.display = 'none';
    document.getElementById('new-tenant-name').focus();
}

function hideCreateTenantForm() {
    document.getElementById('create-tenant-form').style.display = 'none';
    document.getElementById('create-tenant-btn').style.display = 'inline-block';
    document.getElementById('new-tenant-name').value = '';
    document.getElementById('new-tenant-description').value = '';
    document.getElementById('new-tenant-admin-emails').value = '';
    document.getElementById('new-tenant-iam-access-key').value = '';
    document.getElementById('new-tenant-iam-secret-key').value = '';
}

async function createTenant() {
    const nameEl = document.getElementById('new-tenant-name');
    const name = nameEl ? nameEl.value.trim() : '';
    const description = document.getElementById('new-tenant-description').value.trim();
    const adminEmailsText = document.getElementById('new-tenant-admin-emails').value.trim();
    const iamAccessKey = document.getElementById('new-tenant-iam-access-key').value.trim();
    const iamSecretKey = document.getElementById('new-tenant-iam-secret-key').value.trim();

    if (!name) {
        showToast('Tenant name is required', 'error');
        return;
    }

    if (name.length > 50) {
        showToast('Tenant name must be 50 characters or less', 'error');
        return;
    }

    // Parse admin emails - split by newlines and filter empty lines
    const adminEmails = adminEmailsText
        .split('\n')
        .map(email => email.trim())
        .filter(email => email.length > 0);

    if (adminEmails.length === 0) {
        showToast('At least one admin email is required', 'error');
        return;
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    for (const email of adminEmails) {
        if (!emailRegex.test(email)) {
            showToast(`Invalid email format: ${email}`, 'error');
            return;
        }
    }

    try {
        const payload = {
            name: name,
            description: description || undefined,
            admin_emails: adminEmails,
            iam_access_key: iamAccessKey,
            iam_secret_key: iamSecretKey
        };

        const response = await fetch(`${CONFIG.gatewayUrl}/tenants`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${state.token}`
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to create tenant');
        }

        const result = await response.json();
        let message = `Tenant "${result.name}" created successfully!`;
        if (!iamAccessKey) {
            message += ' (IAM credentials can be added later)';
        }
        showToast(message, 'success');
        
        // Hide the form and reload tenants
        hideCreateTenantForm();
        loadTenants();
        
    } catch (error) {
        console.error('Failed to create tenant:', error);
        showToast(error.message || 'Failed to create tenant', 'error');
    }
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
    // If no tenant is selected and user is authenticated
    if (!CONFIG.tenant && state.token) {
        // If user is a global admin, show dashboard with tenant management tab
        if (state.isGlobalAdmin) {
            // Continue to show dashboard - they can manage tenants from the tab
        } else {
            // Regular user or tenant admin - must select a tenant first
            showTenantSelectionScreen();
            return;
        }
    }
    
    document.getElementById('login-screen').classList.remove('active');
    document.getElementById('dashboard-screen').classList.add('active');
    document.getElementById('tenant-selection-screen').classList.remove('active');
    
    // Update tenant name in header
    updateTenantNameDisplay();
    
    // Load available tenants for switcher (for non-global admins with multiple tenants)
    if (CONFIG.tenant && !state.isGlobalAdmin) {
        loadAvailableTenants();
    }
    
    // Update user info display
    if (state.userInfo) {
        const userEmail = state.userInfo.email || state.userInfo.sub || 'User';
        let roleLabel = '';
        if (state.isGlobalAdmin) {
            roleLabel = ' (Global Admin)';
        } else if (state.actualIsAdmin) {
            roleLabel = ' (Tenant Admin)';
        }
        document.getElementById('user-info').textContent = userEmail + roleLabel;
    }
    
    // Update admin UI elements
    updateAdminUI();
    
    // Load initial data and start health monitoring
    startHealthCheckPolling();
    
    // For global admins without a tenant, show tenants tab by default
    if (state.isGlobalAdmin && !CONFIG.tenant) {
        switchTab('tenants');
    } else {
        loadCredentials();
    }
}

// Update UI based on admin status
function updateAdminUI() {
    const isTenantAdmin = state.actualIsAdmin && !state.isGlobalAdmin;
    const isGlobalAdmin = state.isGlobalAdmin;
    const inTenantContext = !!CONFIG.tenant;
    
    console.log('Updating UI with roles:', {
        isTenantAdmin,
        isGlobalAdmin,
        actualIsAdmin: state.actualIsAdmin,
        inTenantContext
    });
    
    // Show/hide credentials tab based on whether we're on a tenant page
    const credentialsTab = document.querySelector('.tab[data-tab="credentials"]');
    if (credentialsTab) {
        if (CONFIG.tenant) {
            credentialsTab.style.display = 'block';
        } else {
            credentialsTab.style.display = 'none';
        }
    }
    
    // Show/hide tenant admin elements (policies, roles)
    document.querySelectorAll('.tenant-admin-only').forEach(el => {
        el.style.display = isTenantAdmin ? 'block' : 'none';
    });
    
    // Show/hide global admin elements (tenants tab)
    document.querySelectorAll('.global-admin-only').forEach(el => {
        el.style.display = isGlobalAdmin ? 'block' : 'none';
    });
    
    // Show/hide global admin elements (tenants)
    document.querySelectorAll('.global-admin-only').forEach(el => {
        el.style.display = isGlobalAdmin ? 'block' : 'none';
    });
    
    // Show/hide admin-only elements (both types of admins)
    document.querySelectorAll('.admin-only').forEach(el => {
        el.style.display = state.actualIsAdmin ? 'block' : 'none';
    });
    
    // If on an invalid tab for current role, switch to appropriate tab
    const activeTab = document.querySelector('.tab.active');
    if (activeTab) {
        const tabName = activeTab.dataset.tab;
        if ((tabName === 'policies' || tabName === 'roles') && !isTenantAdmin) {
            switchTab(CONFIG.tenant ? 'credentials' : 'tenants');
        } else if (tabName === 'tenants' && !isGlobalAdmin) {
            switchTab(CONFIG.tenant ? 'credentials' : 'tenants');
        } else if (tabName === 'credentials' && !CONFIG.tenant) {
            switchTab('tenants');
        }
    }
}

// Update tenant name display in header
function updateTenantNameDisplay() {
    const tenantNameElement = document.getElementById('tenant-name');
    
    if (CONFIG.tenant) {
        tenantNameElement.textContent = CONFIG.tenant;
        tenantNameElement.style.display = 'inline-block';
    } else {
        tenantNameElement.style.display = 'none';
    }
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
        const redirectUri = window.location.origin + '/redirect_uri';
        sessionStorage.setItem('redirect_uri', redirectUri);
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
    localStorage.removeItem('is_admin');
    localStorage.removeItem('is_global_admin');
    
    showLoginScreen();
    showToast('Logged out successfully', 'success');
}

function handleSwitchTenant() {
    // Navigate back to root to select a different tenant
    window.location.href = '/';
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
        case 'tenants':
            loadTenants();
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

// Helper function to get authentication headers
function getAuthHeaders() {
    const headers = {
        'Content-Type': 'application/json'
    };
    
    if (state.token) {
        headers['Authorization'] = `Bearer ${state.token}`;
    }
    
    return headers;
}

// API Calls
async function apiCall(endpoint, options = {}) {
    // Prepend tenant prefix if tenant is configured and not explicitly skipped
    let fullEndpoint = endpoint;
    if (CONFIG.tenant && !options.skipTenantPrefix) {
        // Remove leading slash from endpoint if present
        const cleanEndpoint = endpoint.startsWith('/') ? endpoint.substring(1) : endpoint;
        fullEndpoint = `/tenant/${CONFIG.tenant}/${cleanEndpoint}`;
    }
    
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (state.token) {
        headers['Authorization'] = `Bearer ${state.token}`;
        console.log('API call with auth:', fullEndpoint);
    } else {
        console.log('API call without auth:', fullEndpoint);
    }
    
    // Add credential header for S3 operations
    if (state.selectedCredential && endpoint.startsWith('/s3/')) {
        headers['X-S3-Credential-AccessKey'] = state.selectedCredential;
        console.log('Adding credential header:', state.selectedCredential);
    }
    
    showLoadingSpinner();
    
    try {
        const response = await fetch(`${CONFIG.gatewayUrl}${fullEndpoint}`, {
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
        if (statusEl) {
            statusEl.classList.add('connected');
            statusEl.querySelector('span:last-child').textContent = 'Connected';
        }
        
        const versionEl = document.getElementById('api-version');
        if (versionEl) {
            versionEl.textContent = data.version || '1.0.0';
        }
        
        // Update health indicator
        updateHealthIndicator(data);
    } catch {
        showToast('Cannot connect to gateway', 'error');
        updateHealthIndicator({ healthy: false });
    }
}

// Update health indicator in header
function updateHealthIndicator(healthData) {
    const indicator = document.getElementById('health-indicator');
    if (!indicator) return;
    
    const isHealthy = healthData.healthy !== false;
    const healthText = indicator.querySelector('.health-text');
    
    // Update indicator class
    indicator.className = 'health-indicator ' + (isHealthy ? 'healthy' : 'unhealthy');
    
    // Update text
    if (isHealthy) {
        healthText.textContent = 'Healthy';
    } else {
        healthText.textContent = 'Unhealthy';
    }
    
    // Build tooltip with details
    let tooltip = `System Status: ${isHealthy ? 'Healthy' : 'Unhealthy'}`;
    
    if (healthData.sram_connected !== undefined) {
        tooltip += `\nSRAM: ${healthData.sram_connected ? 'Connected' : 'Disconnected'}`;
        if (healthData.sram_error) {
            tooltip += `\n  Error: ${healthData.sram_error}`;
        }
    }
    
    if (healthData.tenant_health) {
        const tenantCount = Object.keys(healthData.tenant_health).length;
        const healthyCount = Object.values(healthData.tenant_health).filter(t => t.healthy).length;
        tooltip += `\nTenants: ${healthyCount}/${tenantCount} healthy`;
        
        // Show details for unhealthy tenants
        Object.entries(healthData.tenant_health).forEach(([name, health]) => {
            if (!health.healthy) {
                tooltip += `\n  ${name}: `;
                const issues = [];
                if (!health.admin_accepted) issues.push('No admin accepted');
                if (!health.iam_working) issues.push('IAM not working');
                tooltip += issues.join(', ');
            }
        });
    }
    
    indicator.title = tooltip;
    
    // Add click handler to show detailed health modal
    indicator.onclick = () => showHealthDetailsModal(healthData);
}

// Show detailed health information in a modal
function showHealthDetailsModal(healthData) {
    const isHealthy = healthData.healthy !== false;
    
    let html = `
        <div class="modal-content">
            <h2>System Health Status</h2>
            <div class="health-details">
                <div class="health-item">
                    <span class="health-label">Overall Status:</span>
                    <span class="health-value ${isHealthy ? 'healthy' : 'unhealthy'}">
                        ${isHealthy ? '✓ Healthy' : '✗ Unhealthy'}
                    </span>
                </div>
    `;
    
    if (healthData.sram_connected !== undefined) {
        html += `
                <div class="health-item">
                    <span class="health-label">SRAM Connection:</span>
                    <span class="health-value ${healthData.sram_connected ? 'healthy' : 'unhealthy'}">
                        ${healthData.sram_connected ? '✓ Connected' : '✗ Disconnected'}
                    </span>
                </div>
        `;
        if (healthData.sram_error) {
            html += `
                <div class="health-item error">
                    <span class="health-label">SRAM Error:</span>
                    <span class="health-value">${healthData.sram_error}</span>
                </div>
            `;
        }
    }
    
    if (healthData.tenant_health) {
        html += `
                <div class="health-item">
                    <h3 style="margin-top: 1rem; margin-bottom: 0.5rem;">Tenant Health</h3>
                </div>
        `;
        
        Object.entries(healthData.tenant_health).forEach(([name, health]) => {
            html += `
                <div class="health-item tenant-health">
                    <span class="health-label">${name}:</span>
                    <span class="health-value ${health.healthy ? 'healthy' : 'unhealthy'}">
                        ${health.healthy ? '✓ Healthy' : '✗ Unhealthy'}
                    </span>
                    <div class="tenant-health-details">
                        <span>Admin Accepted: ${health.admin_accepted ? '✓' : '✗'}</span>
                        <span>IAM Working: ${health.iam_working ? '✓' : '✗'}</span>
                    </div>
                </div>
            `;
        });
    }
    
    if (healthData.last_checked) {
        const lastChecked = new Date(healthData.last_checked).toLocaleString();
        html += `
                <div class="health-item" style="margin-top: 1rem; font-size: 0.875rem; color: var(--text-secondary);">
                    Last checked: ${lastChecked}
                </div>
        `;
    }
    
    html += `
            </div>
            <button class="btn btn-primary" onclick="closeModal()">Close</button>
        </div>
    `;
    
    showModal(html);
}

// Start health check polling (every 30 seconds)
let healthCheckInterval = null;
function startHealthCheckPolling() {
    if (healthCheckInterval) {
        clearInterval(healthCheckInterval);
    }
    
    // Initial check
    checkGatewayHealth();
    
    // Poll every 30 seconds
    healthCheckInterval = setInterval(() => {
        checkGatewayHealth();
    }, 30000);
}

function stopHealthCheckPolling() {
    if (healthCheckInterval) {
        clearInterval(healthCheckInterval);
        healthCheckInterval = null;
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
        state.userGroups = response.user_groups || []; // Update user groups from response
        
        console.log('Admin status and groups loaded:', {
            isAdmin: state.actualIsAdmin,
            userGroups: state.userGroups,
            userRoles: state.userRoles
        });
        
        // Admin toggle container hidden - admin status determined by backend only
        const toggleContainer = document.getElementById('admin-toggle-container');
        if (toggleContainer) {
            toggleContainer.style.display = 'none';
        }
        
        // Update UI based on admin status
        updateAdminUI();
        
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
    if (!container) {
        console.warn('cred-roles container not found');
        return;
    }
    
    console.log('Loading available roles for credential creation');
    container.innerHTML = '<p style="color: var(--text-secondary);">Loading roles...</p>';
    
    try {
        const response = await apiCall('/settings/roles');
        console.log('Roles API response:', response);
        let roles = response.groups || [];  // Backend returns 'groups' not 'roles'
        
        // Fetch SCIM groups to get displayName and id
        let scimGroupsMap = {};
        try {
            const scimResponse = await apiCall('/settings/sram-groups');
            const scimGroups = scimResponse.Resources || [];
            scimGroupsMap = scimGroups.reduce((map, group) => {
                map[group.id] = {
                    id: group.id,
                    displayName: group.displayName || group.name,
                    shortName: group.shortName
                };
                return map;
            }, {});
        } catch (error) {
            console.error('Failed to load SCIM groups for role display:', error);
        }
        
        // Check if user is admin
        const isAdmin = state.actualIsAdmin;
        
        // Filter roles based on user's OIDC group membership
        // Admin sees all roles, regular users see only roles for groups they belong to
        if (!isAdmin && state.userGroups) {
            roles = roles.filter(role => state.userGroups.includes(role.scim_id));
            
            console.log('Filtered roles for non-admin user:', {
                userGroups: state.userGroups,
                availableRoles: roles.map(r => r.scim_id)
            });
        }
        
        container.innerHTML = '';
        
        if (roles.length > 0) {
            roles.forEach(role => {
                const scimInfo = role.scim_id ? scimGroupsMap[role.scim_id] : null;
                const displayName = scimInfo?.displayName || role.name || role.scim_id || 'Unknown Role';
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
                checkbox.value = role.scim_id || role.name;  // Use SCIM ID for backend validation
                checkbox.className = 'role-checkbox';
                checkbox.style.flex = '0 0 10%';
                checkbox.style.margin = '0';
                
                const textDiv = document.createElement('div');
                textDiv.style.flex = '1';
                textDiv.style.paddingLeft = '0.5rem';
                
                const span = document.createElement('span');
                span.style.fontWeight = 'bold';
                span.textContent = displayName.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                
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
            const message = isAdmin 
                ? 'No roles available' 
                : 'No roles available for your groups. Contact your administrator.';
            container.innerHTML = `<p style="color: var(--text-secondary); font-size: 0.875rem;">${message}</p>`;
        }
    } catch (error) {
        console.error('Failed to load roles:', error);
        const errorMsg = error.message.includes('403') || error.message.includes('Forbidden')
            ? 'You do not have permission to view roles'
            : 'Failed to load roles';
        container.innerHTML = `<p style="color: var(--danger-color); font-size: 0.875rem;">${errorMsg}</p>`;
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
        if (fullCred.groups && fullCred.groups.length > 0) {
            policiesContainer.innerHTML = fullCred.groups.map(role => `
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
                groups: selectedRoles  // Backend expects 'groups' field
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

// Policies Management
// Policies Management
async function loadPolicies() {
    const listEl = document.getElementById('policies-list');
    listEl.innerHTML = '<div class="empty-state">Loading policies...</div>';
    
    try {
        const response = await apiCall('/settings/policies');
        let policies = response.policies || [];
        
        // Use simulated admin status for filtering
        const isAdmin = state.actualIsAdmin;
        
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
                        <button class="btn-icon admin-only" onclick="editPolicy('${policy.name}')" title="Edit">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                            </svg>
                        </button>
                        <button class="btn-icon btn-danger admin-only" onclick="deletePolicy('${policy.name}')" title="Delete">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polyline points="3 6 5 6 21 6"></polyline>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                            </svg>
                        </button>
                    </div>
                </div>
            `).join('');
        }
        
        // Update admin UI for newly created elements
        updateAdminUI();
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

// ===== GROUP MANAGEMENT =====

async function loadRoles() {
    try {
        // Fetch roles
        const rolesResponse = await apiCall('/settings/roles');
        const roles = rolesResponse.groups || [];
        
        const rolesList = document.getElementById('roles-list');
        
        // Check if we have any roles
        if (roles.length === 0) {
            rolesList.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 2rem;">No roles configured yet. Create one to map SRAM groups to policies.</p>';
            return;
        }
        
        // Fetch SCIM groups to get displayName and id
        let scimGroupsMap = {};
        try {
            const scimResponse = await apiCall('/settings/sram-groups');
            const scimGroups = scimResponse.Resources || [];
            scimGroupsMap = scimGroups.reduce((map, group) => {
                map[group.id] = {
                    id: group.id,
                    displayName: group.displayName || group.name,
                    shortName: group.shortName
                };
                return map;
            }, {});
        } catch (error) {
            console.error('Failed to load SCIM groups for display:', error);
        }
        
        let html = '';
        
        // Display roles
        html += roles.map(role => {
            const scimInfo = role.scim_id ? scimGroupsMap[role.scim_id] : null;
            const displayName = scimInfo?.displayName || role.name;
            const scimId = role.scim_id || 'Unknown';
            
            return `
            <div class="credential-card">
                <div class="credential-info">
                    <h4>
                        ${escapeHtml(displayName)} 
                        ${getBackendStatusBadge(role.backend_status)}
                    </h4>
                    <div class="credential-meta" style="font-size: 0.75rem; color: var(--text-secondary);">
                        SRAM Group ID: ${escapeHtml(scimId)}
                        ${scimInfo?.shortName ? ` (${escapeHtml(scimInfo.shortName)})` : ''}
                    </div>
                    ${role.description ? `<div class="credential-meta" style="margin-top: 0.25rem;">${escapeHtml(role.description)}</div>` : ''}
                    <div class="credential-meta" style="margin-top: 0.5rem;">
                        <strong>Policies:</strong>
                        ${role.policies && role.policies.length > 0 
                            ? role.policies.map(p => `<span class="policy-badge">${escapeHtml(p)}</span>`).join(' ')
                            : '<em>No policies assigned</em>'}
                    </div>
                </div>
                <div class="credential-actions">
                    <button class="btn-icon admin-only" onclick="editRole('${escapeHtml(role.scim_id)}')" title="Edit Group">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                        </svg>
                    </button>
                    <button class="btn-icon btn-danger admin-only" onclick="deleteRole('${escapeHtml(role.scim_id)}')" title="Delete Group">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                            <polyline points="3 6 5 6 21 6"></polyline>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                        </svg>
                    </button>
                </div>
            </div>
        `;
        }).join('');
        
        rolesList.innerHTML = html;
        
        // Update admin UI for newly created elements
        updateAdminUI();
    } catch (error) {
        document.getElementById('roles-list').innerHTML = 
            '<p style="text-align: center; color: var(--error-color); padding: 2rem;">Failed to load groups</p>';
        showToast('Failed to load groups: ' + error.message, 'error');
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

async function showCreateGroupModal() {
    const modal = document.getElementById('group-modal');
    document.getElementById('group-modal-title').textContent = 'Create New Role';
    document.getElementById('group-name-select').value = '';
    document.getElementById('group-description').value = '';
    
    state.editingRole = null;
    state.roleSelectedPolicies = [];
    
    // Load available SCIM groups for selection
    await loadAvailableSCIMGroups();
    
    // Load available policies for selection
    await loadPoliciesForGroupModal();
    
    modal.style.display = 'flex';
}

async function loadAvailableSCIMGroups() {
    try {
        // Small delay to ensure role deletion has propagated
        await new Promise(resolve => setTimeout(resolve, 500));

        // Get existing roles (SCIM groups with assigned policies) to filter them out
        const rolesResponse = await apiCall('/settings/roles');
        const existingScimIds = (rolesResponse.groups || []).map(r => r.scim_id).filter(id => id);

        // Get SCIM groups from SRAM
        const groupsResponse = await apiCall('/settings/sram-groups');
        const scimGroups = groupsResponse.Resources || [];

        // Filter out groups that already have roles assigned
        const availableGroups = scimGroups.filter(g => !existingScimIds.includes(g.id));

        const select = document.getElementById('group-name-select');
        select.innerHTML = '<option value="">-- Select an SRAM group --</option>';

        if (availableGroups.length === 0) {
            select.innerHTML += '<option value="" disabled>No available SRAM groups (all groups already have roles)</option>';
        } else {
            availableGroups.forEach(group => {
                const name = group.displayName || group.name;
                const shortName = group.shortName ? ` (${group.shortName})` : '';
                // Store both the display name and the ID in data attributes
                select.innerHTML += `<option value="${escapeHtml(group.id)}" data-name="${escapeHtml(name)}">${escapeHtml(name)}${shortName}</option>`;
            });
        }
    } catch (error) {
        console.error('Failed to load SRAM groups:', error);
        const select = document.getElementById('group-name-select');
        select.innerHTML = '<option value="">Failed to load SRAM groups</option>';
    }
}

async function loadPoliciesForGroupModal() {
    try {
        const response = await apiCall('/settings/policies');
        const policies = response.policies || [];
        
        const selectedPolicies = state.roleSelectedPolicies || [];
        
        const selector = document.getElementById('group-policies-selector');
        
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
    const selectEl = document.getElementById('group-name-select');
    const scimGroupId = selectEl.value.trim();
    const description = document.getElementById('group-description').value.trim();
    const policies = state.roleSelectedPolicies || [];
    
    if (!scimGroupId) {
        showToast('Please select an SRAM group', 'error');
        return;
    }
    
    if (policies.length === 0) {
        showToast('Please select at least one policy for this role', 'error');
        return;
    }
    
    try {
        const isEdit = state.editingRole !== null;
        const method = isEdit ? 'PUT' : 'POST';
        const endpoint = isEdit ? `/settings/roles/${state.editingRole}` : '/settings/roles';
        
        // For new roles, we use the SCIM group ID directly from the select value
        let requestBody;
        if (isEdit) {
            // For edit, just send description and policies (SCIM ID doesn't change)
            requestBody = {
                description,
                policies
            };
        } else {
            // For create, send the SCIM group ID
            requestBody = {
                scim_group_id: scimGroupId,
                description,
                policies
            };
        }
        
        await apiCall(endpoint, {
            method,
            body: JSON.stringify(requestBody)
        });
        
        // Re-enable the select in case it was disabled during edit
        document.getElementById('group-name-select').disabled = false;
        
        hideModals();
        showToast(`Group ${isEdit ? 'updated' : 'created'} successfully!`, 'success');
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

async function deleteRole(scimId) {
    if (!confirm(`Are you sure you want to delete this group?\n\nCredentials with this group will lose their policy mappings.`)) {
        return;
    }
    
    try {
        await apiCall(`/settings/roles/${scimId}`, { method: 'DELETE' });
        showToast('Group deleted successfully', 'success');
        loadRoles();
    } catch (error) {
        showToast('Failed to delete group: ' + error.message, 'error');
    }
}

async function editRole(scimId) {
    try {
        // Fetch the current group data
        const response = await apiCall(`/settings/roles/${scimId}`);
        const group = response.group;
        
        // Populate the modal with existing data
        document.getElementById('group-modal-title').textContent = 'Edit Role';
        
        // Load available SCIM groups first, then select the current one
        await loadAvailableSCIMGroups();
        
        // Disable the group selection for editing (can't change the group)
        const selectEl = document.getElementById('group-name-select');
        selectEl.disabled = true;
        
        // Add the current group to the select if it's not already there
        let optionExists = false;
        for (let i = 0; i < selectEl.options.length; i++) {
            if (selectEl.options[i].value === scimId) {
                optionExists = true;
                selectEl.selectedIndex = i;
                break;
            }
        }
        
        // If the current group is not in the available options (shouldn't happen for editing), add it
        if (!optionExists) {
            const scimInfo = state.scimGroupsMap?.[scimId];
            const displayName = scimInfo?.displayName || group.name || scimId;
            selectEl.innerHTML += `<option value="${escapeHtml(scimId)}">${escapeHtml(displayName)}</option>`;
            selectEl.value = scimId;
        }
        
        document.getElementById('group-description').value = group.description || '';
        
        // Set selected policies
        state.roleSelectedPolicies = group.policies || [];
        
        // Update policy checkboxes
        await loadPoliciesForGroupModal();
        
        // Set editing state
        state.editingRole = scimId;
        
        // Show the modal
        showModal('group-modal');
        
    } catch (error) {
        showToast('Failed to load role for editing: ' + error.message, 'error');
    }
}

// Expose policy and group functions to global scope
window.viewPolicy = viewPolicy;
window.editPolicy = editPolicy;
window.deletePolicy = deletePolicy;
window.showCreatePolicyModal = showCreatePolicyModal;
window.validatePolicyJSON = validatePolicyJSON;
window.showCreateGroupModal = showCreateGroupModal;
window.editRole = editRole;
window.deleteRole = deleteRole;
window.toggleRolePolicy = toggleRolePolicy;

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

// ===== TENANT MANAGEMENT =====

// Helper function to generate health status badge
function getHealthStatusBadge(health) {
    if (!health) {
        return '<span class="badge badge-secondary" style="font-size: 0.75rem;">Unknown</span>';
    }
    
    if (health.healthy) {
        return '<span class="badge badge-success" style="font-size: 0.75rem;">Healthy</span>';
    }
    
    return '<span class="badge badge-error" style="font-size: 0.75rem;">Unhealthy</span>';
}

// Helper function to generate detailed health info
function getTenantHealthDetails(health) {
    if (!health) return '';
    
    const details = [];
    
    if (health.sram_configured) {
        const adminIcon = health.admin_accepted 
            ? '<span style="color: var(--success-color);">✓</span>' 
            : '<span style="color: var(--error-color);">✗</span>';
        details.push(`${adminIcon} Admin: ${health.admin_accepted ? 'Accepted' : 'Pending'}`);
    }
    
    const iamIcon = health.iam_working 
        ? '<span style="color: var(--success-color);">✓</span>' 
        : health.sram_configured && !health.iam_working 
        ? '<span style="color: var(--warning-color);">⚠</span>'
        : '<span style="color: var(--text-secondary);">-</span>';
    details.push(`${iamIcon} IAM: ${health.iam_working ? 'Working' : 'Not Configured'}`);
    
    if (details.length > 0) {
        return `<div class="tenant-health-details" style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 8px; display: flex; gap: 15px;">${details.join('')}</div>`;
    }
    
    return '';
}

async function loadTenants() {
    const listEl = document.getElementById('tenants-list');
    listEl.innerHTML = '<div class="empty-state">Loading tenants...</div>';

    try {
        // Fetch tenants and health status in parallel
        const [tenantsResponse, healthResponse] = await Promise.all([
            fetch(`${CONFIG.gatewayUrl}/tenants`, {
                method: 'GET',
                headers: getAuthHeaders()
            }),
            fetch(`${CONFIG.gatewayUrl}/health`)
        ]);
        
        if (!tenantsResponse.ok) {
            throw new Error('Failed to load tenants');
        }
        
        const data = await tenantsResponse.json();
        const tenants = data.tenants || [];
        
        // Get health data if available
        let healthData = {};
        if (healthResponse.ok) {
            const health = await healthResponse.json();
            healthData = health.tenant_health || {};
        }

        if (tenants.length === 0) {
            listEl.innerHTML = `
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                        <path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2z"></path>
                        <path d="M8 5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2H8V5z"></path>
                    </svg>
                    <p>No tenants configured</p>
                    <p style="font-size: 0.875rem; margin-top: 0.5rem;">Create your first tenant to get started</p>
                </div>
            `;
        } else {
            listEl.innerHTML = tenants.map(tenant => {
                const health = healthData[tenant.name];
                const healthStatus = getHealthStatusBadge(health);
                
                return `
                <div class="tenant-card">
                    <div class="tenant-info">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <h4>${tenant.name}</h4>
                            ${healthStatus}
                        </div>
                        <div class="tenant-meta">${tenant.description || 'No description'}</div>
                        ${health ? getTenantHealthDetails(health) : ''}
                    </div>
                    <div class="tenant-actions">
                        <button class="btn-icon" onclick="selectTenant('${tenant.name}')" title="Access Tenant">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M9 18l6-6-6-6"/>
                            </svg>
                        </button>
                        <button class="btn-icon" onclick="inspectTenant('${tenant.name}')" title="View Details">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                        </button>
                        <button class="btn-icon global-admin-only" onclick="editTenant('${tenant.name}')" title="Edit">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                            </svg>
                        </button>
                        <button class="btn-icon btn-danger global-admin-only" onclick="deleteTenant('${tenant.name}')" title="Delete">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polyline points="3 6 5 6 21 6"></polyline>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                            </svg>
                        </button>
                    </div>
                </div>`
            }).join('');
        }
        
        // Update admin UI for newly created elements
        updateAdminUI();
    } catch (error) {
        listEl.innerHTML = `<div class="empty-state">Failed to load tenants: ${error.message}</div>`;
    }
}

function showCreateTenantModal() {
    const modal = document.getElementById('tenant-modal');
    document.getElementById('tenant-modal-title').textContent = 'Create New Tenant';
    document.getElementById('tenant-modal-name').value = '';
    document.getElementById('tenant-modal-name').disabled = false;
    document.getElementById('tenant-description').value = '';
    document.getElementById('tenant-admin-email').value = '';
    document.getElementById('tenant-iam-access-key').value = '';
    document.getElementById('tenant-iam-secret-key').value = '';
    document.getElementById('confirm-save-tenant').textContent = 'Create Tenant';

    state.editingTenant = null;
    modal.style.display = 'flex';
}

async function inspectTenant(name) {
    try {
        // For now, we'll fetch basic tenant info from the list endpoint
        // In the future, we might want a dedicated endpoint for tenant details
        // Always call /tenants at root level (not tenant-prefixed)
        const response = await fetch(`${CONFIG.gatewayUrl}/tenants`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${state.token}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to load tenant details');
        }
        
        const data = await response.json();
        const tenant = data.tenants.find(t => t.name === name);

        if (!tenant) {
            throw new Error('Tenant not found');
        }

        document.getElementById('inspect-tenant-name').textContent = tenant.name;
        document.getElementById('inspect-tenant-description').textContent = tenant.description || 'No description';
        document.getElementById('inspect-tenant-admin-email').textContent = 'Not available'; // Will be populated when we add detail endpoint
        document.getElementById('inspect-tenant-iam-access-key').textContent = '••••••••••••••••';
        document.getElementById('inspect-tenant-iam-secret-key').textContent = '••••••••••••••••••••••••••••••••';

        // Reset secret visibility
        state.tenantSecretKeyVisible = false;
        const secretKeyEl = document.getElementById('inspect-tenant-iam-secret-key');
        secretKeyEl.textContent = '••••••••••••••••••••••••••••••••';
        const iconEl = document.getElementById('tenant-secret-eye-icon');
        iconEl.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';

        // Fetch SRAM invitation status
        await loadSRAMInvitationStatus(name);

        showModal('inspect-tenant-modal');
    } catch (error) {
        console.error('Failed to load tenant details:', error);
        showToast('Failed to load tenant details: ' + error.message, 'error');
    }
}

async function loadSRAMInvitationStatus(tenantName) {
    const container = document.getElementById('sram-invitation-status');
    if (!container) {
        console.error('SRAM invitation status container not found');
        return;
    }

    try {
        const response = await fetch(`${CONFIG.gatewayUrl}/tenants/${tenantName}/sram-invitations`, {
            headers: getAuthHeaders()
        });

        if (!response.ok) {
            if (response.status === 400) {
                // SRAM not enabled
                container.innerHTML = '<p class="text-muted">SRAM integration is not enabled</p>';
                return;
            }
            throw new Error('Failed to load SRAM invitation status');
        }

        const data = await response.json();

        if (!data.invitations || data.invitations.length === 0) {
            container.innerHTML = '<p class="text-muted">No SRAM invitations sent</p>';
            return;
        }

        const invitationsHTML = data.invitations.map(invitation => {
            const statusClass = invitation.status === 'accepted' ? 'success' : 
                              invitation.status === 'declined' ? 'error' : 'warning';
            const statusText = invitation.status.charAt(0).toUpperCase() + invitation.status.slice(1);
            
            return `
                <div class="invitation-item">
                    <div class="invitation-email">${invitation.email}</div>
                    <span class="badge badge-${statusClass}">${statusText}</span>
                </div>
            `;
        }).join('');

        container.innerHTML = `
            <div class="invitation-list">
                ${invitationsHTML}
            </div>
        `;
    } catch (error) {
        console.error('Failed to load SRAM invitation status:', error);
        container.innerHTML = '<p class="text-error">Failed to load invitation status</p>';
    }
}

async function editTenant(name) {
    try {
        // Fetch detailed tenant information
        const response = await fetch(`${CONFIG.gatewayUrl}/tenants/${name}`, {
            method: 'GET',
            headers: getAuthHeaders()
        });
        
        if (!response.ok) {
            throw new Error('Failed to load tenant details');
        }
        
        const tenant = await response.json();

        document.getElementById('tenant-modal-title').textContent = `Edit Tenant: ${name}`;
        document.getElementById('tenant-modal-name').value = tenant.name;
        document.getElementById('tenant-modal-name').disabled = true; // Don't allow name changes
        document.getElementById('tenant-description').value = tenant.description || '';
        document.getElementById('tenant-admin-email').value = tenant.admin_emails && tenant.admin_emails.length > 0 ? tenant.admin_emails.join(' ') : '';
        
        // Display admin emails (read-only for reference)
        const adminEmailsDisplay = document.getElementById('tenant-admin-emails-display');
        if (tenant.admin_emails && tenant.admin_emails.length > 0) {
            adminEmailsDisplay.innerHTML = tenant.admin_emails.map(email => 
                `<div class="admin-email-item">${email}</div>`
            ).join('');
        } else {
            adminEmailsDisplay.innerHTML = '<div class="form-hint">No admin emails configured</div>';
        }
        
        // Display IAM credentials info
        if (tenant.has_iam_credentials) {
            document.getElementById('tenant-iam-access-key').placeholder = tenant.iam_access_key || 'AKIA... (leave empty to keep existing)';
            document.getElementById('tenant-iam-secret-key').placeholder = '(leave empty to keep existing)';
            document.getElementById('tenant-iam-current-value').textContent = 
                `Current: ${tenant.iam_access_key} / ${tenant.iam_secret_key_masked}`;
        } else {
            document.getElementById('tenant-iam-access-key').placeholder = 'AKIA... (optional)';
            document.getElementById('tenant-iam-secret-key').placeholder = '(optional)';
            document.getElementById('tenant-iam-current-value').textContent = 'No IAM credentials configured';
        }
        
        // Clear input fields (user must re-enter to change)
        document.getElementById('tenant-iam-access-key').value = '';
        document.getElementById('tenant-iam-secret-key').value = '';
        
        document.getElementById('confirm-save-tenant').textContent = 'Update Tenant';

        state.editingTenant = name;
        
        // Load SRAM invitation status if available
        await loadSRAMInvitations(name);
        
        document.getElementById('tenant-modal').style.display = 'flex';
    } catch (error) {
        console.error('Failed to load tenant for editing:', error);
        showToast('Failed to load tenant: ' + error.message, 'error');
    }
}

async function loadSRAMInvitations(tenantName) {
    try {
        const response = await fetch(`${CONFIG.gatewayUrl}/tenants/${tenantName}/sram-invitations`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${state.token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            // If SRAM is not enabled or error, hide the section
            document.getElementById('sram-invitations-section').style.display = 'none';
            return;
        }

        const data = await response.json();
        
        // Show invitations section even if there are no invitations
        // This ensures refresh buttons are always available for tenants with SRAM enabled
        document.getElementById('sram-invitations-section').style.display = 'block';
        
        // Render invitations or show "no invitations" message
        const listEl = document.getElementById('sram-invitations-list');
        if (!data.invitations || data.invitations.length === 0) {
            listEl.innerHTML = '<div class="form-hint">No invitations found. Click "Refresh Status" to check for new invitations.</div>';
            state.currentInvitations = [];
        } else {
            listEl.innerHTML = data.invitations.map(inv => {
                const statusBadge = inv.status === 'accepted' 
                    ? '<span class="badge badge-success">Accepted</span>'
                    : inv.status === 'pending'
                    ? '<span class="badge badge-warning">Pending</span>'
                    : '<span class="badge badge-error">Declined</span>';
                
                const usernameDisplay = inv.sram_username 
                    ? `<div class="invitation-username">SRAM Username: ${inv.sram_username}</div>`
                    : '';
                
                const extraClass = inv.status === 'accepted' ? 'invitation-accepted' : '';
                
                return `
                    <div class="invitation-item ${extraClass}" data-invitation-id="${inv.id}" data-email="${inv.email}">
                        <div>
                            <div class="invitation-email">${inv.email}</div>
                            ${usernameDisplay}
                        </div>
                        <div>${statusBadge}</div>
                    </div>
                `;
            }).join('');

            // Store invitations for later reference
            state.currentInvitations = data.invitations;
        }
    } finally {
        // Re-enable buttons after loading
        document.getElementById('refresh-invitations').disabled = false;
        document.getElementById('sync-sram-admins').disabled = false;
    }
}

async function refreshInvitationStatus() {
    if (!state.editingTenant) {
        return;
    }
    
    const btn = document.getElementById('refresh-invitations');
    btn.disabled = true;
    btn.textContent = 'Refreshing...';
    
    try {
        await loadSRAMInvitations(state.editingTenant);
        showToast('Invitation status refreshed', 'success');
    } catch (error) {
        showToast('Failed to refresh invitation status: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Refresh Status';
    }
}

async function syncSRAMAdmins() {
    if (!state.editingTenant) {
        return;
    }
    
    const btn = document.getElementById('sync-sram-admins');
    btn.disabled = true;
    btn.textContent = 'Syncing...';
    
    try {
        const response = await fetch(`${CONFIG.gatewayUrl}/tenants/${state.editingTenant}/sync-sram-admins`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${state.token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to sync SRAM admins');
        }

        const data = await response.json();
        
        if (data.synced === 0) {
            showToast(data.message || 'No new admins to sync', 'info');
        } else {
            showToast(`Synced ${data.synced} new admin(s): ${data.new_admins.join(', ')}`, 'success');
        }
        
        // Reload invitation status to show updated state
        await loadSRAMInvitations(state.editingTenant);
        
    } catch (error) {
        showToast('Failed to sync SRAM admins: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Sync Accepted Admins to Config';
    }
}


async function handleSaveTenant() {
    const name = document.getElementById('tenant-modal-name').value.trim();
    const description = document.getElementById('tenant-description').value.trim();
    const adminEmailsText = document.getElementById('tenant-admin-email').value.trim();
    const iamAccessKey = document.getElementById('tenant-iam-access-key').value.trim();
    const iamSecretKey = document.getElementById('tenant-iam-secret-key').value.trim();

    // Parse admin emails from input field (space-separated)
    const adminEmails = adminEmailsText.split(/\s+/)
        .map(email => email.trim())
        .filter(email => email.length > 0);

    if (!name) {
        showToast('Tenant name is required', 'error');
        return;
    }

    if (adminEmails.length === 0) {
        showToast('At least one admin email is required', 'error');
        return;
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    for (const email of adminEmails) {
        if (!emailRegex.test(email)) {
            showToast(`Invalid email format: ${email}`, 'error');
            return;
        }
    }

    try {
        let response;
        if (state.editingTenant) {
            // Update existing tenant - use new format with admin_emails array
            const payload = {
                description: description,
                admin_emails: adminEmails
            };
            
            // Only include IAM keys if both are provided
            if (iamAccessKey && iamSecretKey) {
                payload.iam_access_key = iamAccessKey;
                payload.iam_secret_key = iamSecretKey;
            }
            
            response = await fetch(`${CONFIG.gatewayUrl}/tenants/${state.editingTenant}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${state.token}`
                },
                body: JSON.stringify(payload)
            });
        } else {
            // Create new tenant - use new format with admin_emails array
            const payload = {
                name: name,
                description: description,
                admin_emails: adminEmails
            };
            
            // Only include IAM keys if both are provided
            if (iamAccessKey && iamSecretKey) {
                payload.iam_access_key = iamAccessKey;
                payload.iam_secret_key = iamSecretKey;
            }
            
            response = await fetch(`${CONFIG.gatewayUrl}/tenants`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${state.token}`
                },
                body: JSON.stringify(payload)
            });
        }

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to save tenant');
        }

        const result = await response.json();
        let message = `Tenant "${result.name || name}" ${state.editingTenant ? 'updated' : 'created'} successfully!`;
        if (!iamAccessKey && !state.editingTenant) {
            message += ' (IAM credentials can be added later)';
        }
        showToast(message, 'success');

        hideModals();
        loadTenants(); // Reload tenant list
    } catch (error) {
        console.error('Failed to save tenant:', error);
        showToast(error.message || 'Failed to save tenant', 'error');
    }
}

async function deleteTenant(name) {
    if (!confirm(`Are you sure you want to delete tenant "${name}"?\n\nThis will:\n- Delete all tenant data and configuration\n- Remove all policies and roles\n- Delete all user credentials\n\nThis action cannot be undone.`)) {
        return;
    }

    try {
        const response = await fetch(`${CONFIG.gatewayUrl}/tenants/${name}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to delete tenant');
        }

        showToast('Tenant deleted successfully', 'success');
        loadTenants(); // Reload tenant list
    } catch (error) {
        showToast('Failed to delete tenant: ' + error.message, 'error');
    }
}

function toggleTenantSecretKeyVisibility() {
    const secretKeyEl = document.getElementById('inspect-tenant-iam-secret-key');
    const iconEl = document.getElementById('tenant-secret-eye-icon');

    if (!state.currentTenantSecretKey) {
        showToast('Secret key not available', 'info');
        return;
    }

    state.tenantSecretKeyVisible = !state.tenantSecretKeyVisible;

    if (state.tenantSecretKeyVisible) {
        // Show the actual secret key
        secretKeyEl.textContent = state.currentTenantSecretKey;
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
window.inspectTenant = inspectTenant;
window.editTenant = editTenant;
window.deleteTenant = deleteTenant;
window.refreshTenantSRAM = refreshTenantSRAM;
window.showCreateTenantModal = showCreateTenantModal;
window.handleSaveTenant = handleSaveTenant;
window.toggleTenantSecretKeyVisibility = toggleTenantSecretKeyVisibility;window.refreshInvitationStatus = refreshInvitationStatus;window.syncSRAMAdmins = syncSRAMAdmins;
