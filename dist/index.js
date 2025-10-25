var __create = Object.create;
var __getProtoOf = Object.getPrototypeOf;
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __toESM = (mod, isNodeMode, target) => {
  target = mod != null ? __create(__getProtoOf(mod)) : {};
  const to = isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target;
  for (let key of __getOwnPropNames(mod))
    if (!__hasOwnProp.call(to, key))
      __defProp(to, key, {
        get: () => mod[key],
        enumerable: true
      });
  return to;
};
var __moduleCache = /* @__PURE__ */ new WeakMap;
var __toCommonJS = (from) => {
  var entry = __moduleCache.get(from), desc;
  if (entry)
    return entry;
  entry = __defProp({}, "__esModule", { value: true });
  if (from && typeof from === "object" || typeof from === "function")
    __getOwnPropNames(from).map((key) => !__hasOwnProp.call(entry, key) && __defProp(entry, key, {
      get: () => from[key],
      enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
    }));
  __moduleCache.set(from, entry);
  return entry;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, {
      get: all[name],
      enumerable: true,
      configurable: true,
      set: (newValue) => all[name] = () => newValue
    });
};

// index.ts
var exports_allauth_react = {};
__export(exports_allauth_react, {
  useWebAuthnSignup: () => useWebAuthnSignup,
  useWebAuthnReauthenticate: () => useWebAuthnReauthenticate,
  useWebAuthnLogin: () => useWebAuthnLogin,
  useWebAuthnCredentials: () => useWebAuthnCredentials,
  useWebAuthnAuthenticate: () => useWebAuthnAuthenticate,
  useVerifyPhone: () => useVerifyPhone,
  useVerifyEmail: () => useVerifyEmail,
  useUpdatePhoneNumber: () => useUpdatePhoneNumber,
  useSocialAuth: () => useSocialAuth,
  useSignup: () => useSignup,
  useSetPrimaryEmail: () => useSetPrimaryEmail,
  useResetPassword: () => useResetPassword,
  useResendPhoneVerification: () => useResendPhoneVerification,
  useResendEmailVerification: () => useResendEmailVerification,
  useRequestPasswordReset: () => useRequestPasswordReset,
  useRequestLoginCode: () => useRequestLoginCode,
  useRequestEmailVerification: () => useRequestEmailVerification,
  useRemovePhoneNumber: () => useRemovePhoneNumber,
  useRemoveEmailAddress: () => useRemoveEmailAddress,
  useRegenerateRecoveryCodes: () => useRegenerateRecoveryCodes,
  useReauthenticate: () => useReauthenticate,
  useProviderToken: () => useProviderToken,
  useProviderSignupData: () => useProviderSignupData,
  useProviderSignup: () => useProviderSignup,
  useProviderRedirect: () => useProviderRedirect,
  useProviderAccounts: () => useProviderAccounts,
  usePhoneNumber: () => usePhoneNumber,
  usePasswordReset: () => usePasswordReset,
  useMfaTrust: () => useMfaTrust,
  useMfaReauthenticate: () => useMfaReauthenticate,
  useMfaAuthenticate: () => useMfaAuthenticate,
  useLogout: () => useLogout,
  useLogin: () => useLogin,
  useListSessions: () => useListSessions,
  useEmailManagement: () => useEmailManagement,
  useEmailAddresses: () => useEmailAddresses,
  useDisconnectProvider: () => useDisconnectProvider,
  useDeleteWebAuthnCredential: () => useDeleteWebAuthnCredential,
  useDeleteSession: () => useDeleteSession,
  useDeactivateTOTP: () => useDeactivateTOTP,
  useConfirmLoginCode: () => useConfirmLoginCode,
  useConfig: () => useConfig,
  useChangePassword: () => useChangePassword,
  useAuthenticators: () => useAuthenticators,
  useAuthTokens: () => useAuthTokens,
  useAuthTokenStore: () => useAuthTokenStore,
  useAuthStatus: () => useAuthStatus,
  useAuth: () => useAuth,
  useAddEmailAddress: () => useAddEmailAddress,
  useActivateTOTP: () => useActivateTOTP,
  initializeClient: () => initializeClient,
  getWebAuthnSignupOptions: () => getWebAuthnSignupOptions,
  getWebAuthnReauthenticateOptions: () => getWebAuthnReauthenticateOptions,
  getWebAuthnLoginOptions: () => getWebAuthnLoginOptions,
  getWebAuthnAuthenticateOptions: () => getWebAuthnAuthenticateOptions,
  getTOTPAuthenticator: () => getTOTPAuthenticator,
  getStorage: () => getStorage,
  getRecoveryCodes: () => getRecoveryCodes,
  getPasswordResetInfo: () => getPasswordResetInfo,
  getEmailVerificationInfo: () => getEmailVerificationInfo,
  getClient: () => getClient,
  getAuthInvalidationKeys: () => getAuthInvalidationKeys,
  getAllInvalidationKeys: () => getAllInvalidationKeys,
  allauthQueryKeys: () => allauthQueryKeys,
  ZustandStorage: () => ZustandStorage,
  HybridStorage: () => HybridStorage,
  CookieStorage: () => CookieStorage,
  AllauthProvider: () => AllauthProvider,
  AllauthClient: () => AllauthClient
});
module.exports = __toCommonJS(exports_allauth_react);

// lib/provider/AllauthProvider.tsx
var import_react = __toESM(require("react"));
var import_react_query = require("@tanstack/react-query");

// lib/api/storage.ts
var import_zustand = require("zustand");
var import_middleware = require("zustand/middleware");
var useAuthTokenStore = import_zustand.create()(import_middleware.persist((set) => ({
  sessionToken: null,
  csrfToken: null,
  setSessionToken: (token) => set({ sessionToken: token }),
  setCSRFToken: (token) => set({ csrfToken: token }),
  clearTokens: () => set({ sessionToken: null, csrfToken: null })
}), {
  name: "allauth-tokens",
  storage: import_middleware.createJSONStorage(() => localStorage),
  partialize: (state) => ({
    sessionToken: state.sessionToken
  })
}));
function getCookie(name) {
  if (typeof document === "undefined")
    return;
  if (document.cookie && document.cookie !== "") {
    const cookies = document.cookie.split(";");
    for (let i = 0;i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === name + "=") {
        return decodeURIComponent(cookie.substring(name.length + 1));
      }
    }
  }
}
function setCookie(name, value, secure = false) {
  if (typeof document === "undefined")
    return;
  try {
    if (value) {
      const encodedValue = encodeURIComponent(value);
      let cookieString = `${name}=${encodedValue}; path=/; samesite=lax`;
      if (secure) {
        cookieString += "; secure";
      }
      document.cookie = cookieString;
    } else {
      let cookieString = `${name}=; path=/; samesite=lax; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
      if (secure) {
        cookieString += "; secure";
      }
      document.cookie = cookieString;
    }
  } catch (error) {
    console.error(`Failed to set ${name} cookie:`, error);
  }
}

class ZustandStorage {
  async getSessionToken() {
    return useAuthTokenStore.getState().sessionToken;
  }
  async setSessionToken(value) {
    useAuthTokenStore.getState().setSessionToken(value);
  }
  async getCSRFToken() {
    return useAuthTokenStore.getState().csrfToken;
  }
  async setCSRFToken(value) {
    useAuthTokenStore.getState().setCSRFToken(value);
  }
}

class CookieStorage {
  useSecure;
  csrfTokenCookieName;
  sessionTokenCookieName;
  constructor(options = {}) {
    this.useSecure = options.apiUrl ? options.apiUrl.startsWith("https:") : typeof window !== "undefined" && window.location.protocol === "https:";
    this.csrfTokenCookieName = options.csrfTokenCookieName || "csrftoken";
    this.sessionTokenCookieName = options.sessionTokenCookieName || "sessiontoken";
  }
  async getSessionToken() {
    return getCookie(this.sessionTokenCookieName) || null;
  }
  async setSessionToken(value) {
    setCookie(this.sessionTokenCookieName, value, this.useSecure);
  }
  async getCSRFToken() {
    return getCookie(this.csrfTokenCookieName) || null;
  }
  async setCSRFToken(value) {
    setCookie(this.csrfTokenCookieName, value, this.useSecure);
  }
}

class HybridStorage {
  zustandStorage;
  cookieStorage;
  constructor(options = {}) {
    this.zustandStorage = new ZustandStorage;
    this.cookieStorage = new CookieStorage(options);
  }
  async getSessionToken() {
    const zustandToken = await this.zustandStorage.getSessionToken();
    if (zustandToken)
      return zustandToken;
    return this.cookieStorage.getSessionToken();
  }
  async setSessionToken(value) {
    await this.zustandStorage.setSessionToken(value);
    await this.cookieStorage.setSessionToken(value);
  }
  async getCSRFToken() {
    const zustandToken = await this.zustandStorage.getCSRFToken();
    if (zustandToken)
      return zustandToken;
    return this.cookieStorage.getCSRFToken();
  }
  async setCSRFToken(value) {
    await this.zustandStorage.setCSRFToken(value);
    await this.cookieStorage.setCSRFToken(value);
  }
}
function useAuthTokens() {
  return useAuthTokenStore((state) => ({
    sessionToken: state.sessionToken,
    csrfToken: state.csrfToken,
    setSessionToken: state.setSessionToken,
    setCSRFToken: state.setCSRFToken,
    clearTokens: state.clearTokens
  }));
}
function getStorage(clientType, apiUrl) {
  if (clientType === "app") {
    return new ZustandStorage;
  } else {
    return new HybridStorage({ apiUrl });
  }
}

// lib/api/client.ts
var clientInstance = null;

class AllauthClient {
  storage;
  csrfTokenUrl;
  clientPath;
  browserPath;
  constructor(apiBaseUrl = "", csrfTokenEndpoint, clientType = "browser", storage) {
    this.clientPath = apiBaseUrl ? `${apiBaseUrl}/_allauth/${clientType}/v1` : `/_allauth/${clientType}/v1`;
    this.browserPath = apiBaseUrl ? `${apiBaseUrl}/_allauth/browser/v1` : `/_allauth/browser/v1`;
    this.storage = storage || getStorage(clientType, apiBaseUrl);
    this.csrfTokenUrl = csrfTokenEndpoint ? apiBaseUrl ? `${apiBaseUrl}${csrfTokenEndpoint}` : csrfTokenEndpoint : "";
  }
  async fetchCSRFToken() {
    if (!this.csrfTokenUrl) {
      return null;
    }
    try {
      const response = await fetch(this.csrfTokenUrl, {
        method: "GET",
        credentials: "include",
        mode: "cors",
        headers: {
          Accept: "application/json"
        }
      });
      if (!response.ok) {
        console.error("Failed to fetch CSRF token:", response.status);
        return null;
      }
      const data = await response.json();
      if (data && data.token) {
        return data.token;
      } else if (data) {
        return data;
      }
      const cookieToken = await this.storage.getCSRFToken();
      if (cookieToken) {
        return cookieToken;
      }
    } catch (error) {
      console.error("Error fetching CSRF token:", error);
      return null;
    }
    return null;
  }
  async fetch(url, options = {}) {
    const headers = new Headers(options.headers || {});
    if (!options.body || !(options.body instanceof FormData)) {
      if (!headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
      }
    }
    if (options.method !== "GET" && options.method !== undefined) {
      let csrfToken = null;
      if (this.csrfTokenUrl) {
        csrfToken = await this.fetchCSRFToken();
      } else {
        csrfToken = await this.storage.getCSRFToken();
      }
      if (csrfToken) {
        headers.set("X-CSRFToken", csrfToken);
        await this.storage.setCSRFToken(csrfToken);
      }
    }
    const sessionToken = await this.storage.getSessionToken();
    if (sessionToken) {
      headers.set("X-Session-Token", sessionToken);
    }
    const response = await fetch(url, {
      ...options,
      headers,
      credentials: options.credentials || "include",
      mode: options.mode || "cors"
    });
    if (response.ok) {
      try {
        const clonedResponse = response.clone();
        const data = await clonedResponse.json();
        if (data?.meta?.session_token) {
          await this.storage.setSessionToken(data.meta.session_token);
        }
      } catch {}
    }
    if (response.status === 410) {
      await this.storage.setSessionToken(null);
    }
    return response;
  }
  async request(path, options = {}) {
    const url = path.startsWith("http") ? path : `${this.clientPath}${path}`;
    const response = await this.fetch(url, options);
    const data = await response.json();
    if (!response.ok && data.errors) {
      throw data;
    }
    return data;
  }
  async getConfiguration() {
    return this.request("/config");
  }
  async getAuthenticationStatus() {
    return this.request("/auth/session");
  }
  async login(data) {
    return this.request("/auth/login", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async logout() {
    return this.request("/auth/session", {
      method: "DELETE"
    });
  }
  async signup(data) {
    return this.request("/auth/signup", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async reauthenticate(data) {
    return this.request("/auth/reauthenticate", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async requestLoginCode(data) {
    return this.request("/auth/code/request", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async confirmLoginCode(data) {
    return this.request("/auth/code/confirm", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async listEmailAddresses() {
    return this.request("/account/email");
  }
  async addEmailAddress(data) {
    return this.request("/account/email", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async removeEmailAddress(data) {
    return this.request("/account/email", {
      method: "DELETE",
      body: JSON.stringify(data)
    });
  }
  async changePrimaryEmailAddress(data) {
    return this.request("/account/email", {
      method: "PATCH",
      body: JSON.stringify(data)
    });
  }
  async requestEmailVerification(data) {
    return this.request("/account/email", {
      method: "PUT",
      body: JSON.stringify(data)
    });
  }
  async getEmailVerificationInfo(key) {
    return this.request(`/auth/email/verify?key=${encodeURIComponent(key)}`);
  }
  async verifyEmail(data) {
    return this.request("/auth/email/verify", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async resendEmailVerification() {
    return this.request("/auth/email/verify/resend", {
      method: "POST"
    });
  }
  async getPhoneNumber() {
    return this.request("/account/phone");
  }
  async updatePhoneNumber(phone) {
    return this.request("/account/phone", {
      method: "PUT",
      body: JSON.stringify({ phone })
    });
  }
  async removePhoneNumber() {
    return this.request("/account/phone", {
      method: "DELETE"
    });
  }
  async verifyPhone(data) {
    return this.request("/auth/phone/verify", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async resendPhoneVerification() {
    return this.request("/auth/phone/verify/resend", {
      method: "POST"
    });
  }
  async requestPassword(data) {
    return this.request("/auth/password/request", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async getPasswordResetInfo(key) {
    return this.request(`/auth/password/reset?key=${encodeURIComponent(key)}`);
  }
  async resetPassword(data) {
    return this.request("/auth/password/reset", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async changePassword(data) {
    return this.request("/account/password/change", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async listProviderAccounts() {
    return this.request("/account/providers");
  }
  async disconnectProviderAccount(data) {
    return this.request("/account/providers", {
      method: "DELETE",
      body: JSON.stringify(data)
    });
  }
  async providerRedirect(provider, callbackUrl, process = "login") {
    const url = `${this.browserPath}/auth/provider/redirect`;
    const form = document.createElement("form");
    form.method = "POST";
    form.action = url;
    let csrfmiddlewaretoken = "";
    if (this.csrfTokenUrl) {
      csrfmiddlewaretoken = await this.fetchCSRFToken() || "";
    } else {
      csrfmiddlewaretoken = await this.storage.getCSRFToken() || "";
    }
    const fields = { provider, callback_url: callbackUrl, process, csrfmiddlewaretoken };
    Object.entries(fields).forEach(([key, value]) => {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = key;
      input.value = value;
      form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
  }
  async providerToken(data) {
    return this.request("/auth/provider/token", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async getProviderSignup() {
    return this.request("/auth/provider/signup");
  }
  async providerSignup(data) {
    return this.request("/auth/provider/signup", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async listAuthenticators() {
    return this.request("/account/authenticators");
  }
  async getTOTPAuthenticator() {
    return this.request("/account/authenticators/totp");
  }
  async activateTOTP(data) {
    return this.request("/account/authenticators/totp", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async deactivateTOTP() {
    return this.request("/account/authenticators/totp", {
      method: "DELETE"
    });
  }
  async listRecoveryCodes() {
    return this.request("/account/authenticators/recovery-codes");
  }
  async regenerateRecoveryCodes() {
    return this.request("/account/authenticators/recovery-codes", {
      method: "POST"
    });
  }
  async mfaAuthenticate(data) {
    return this.request("/auth/2fa/authenticate", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async mfaReauthenticate() {
    return this.request("/auth/2fa/reauthenticate", {
      method: "POST"
    });
  }
  async mfaTrust(data) {
    const url = `${this.browserPath}/auth/2fa/trust`;
    const response = await this.fetch(url, {
      method: "POST",
      body: JSON.stringify(data)
    });
    const result = await response.json();
    if (!response.ok && result.errors) {
      throw result;
    }
    return result;
  }
  async getWebAuthnSignupOptions() {
    return this.request("/auth/webauthn/signup");
  }
  async webAuthnSignup(data) {
    return this.request("/auth/webauthn/signup", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async getWebAuthnLoginOptions() {
    return this.request("/auth/webauthn/login");
  }
  async webAuthnLogin(data) {
    return this.request("/auth/webauthn/login", {
      method: "POST",
      body: JSON.stringify(data)
    });
  }
  async getWebAuthnAuthenticateOptions() {
    return this.request("/auth/webauthn/authenticate");
  }
  async webAuthnAuthenticate(credential) {
    return this.request("/auth/webauthn/authenticate", {
      method: "POST",
      body: JSON.stringify({ credential })
    });
  }
  async getWebAuthnReauthenticateOptions() {
    return this.request("/auth/webauthn/reauthenticate");
  }
  async webAuthnReauthenticate(credential) {
    return this.request("/auth/webauthn/reauthenticate", {
      method: "POST",
      body: JSON.stringify({ credential })
    });
  }
  async listWebAuthnCredentials() {
    return this.request("/account/authenticators/webauthn");
  }
  async deleteWebAuthnCredential(id) {
    return this.request(`/account/authenticators/webauthn`, {
      method: "DELETE",
      body: JSON.stringify({ id })
    });
  }
  async listSessions() {
    return this.request("/auth/sessions");
  }
  async deleteSession(id) {
    const path = id ? `/auth/sessions` : "/auth/session";
    return this.request(path, {
      method: "DELETE",
      body: id ? JSON.stringify({ id }) : undefined
    });
  }
}
function initializeClient(config) {
  if (!clientInstance) {
    const { baseUrl = "", csrfTokenEndpoint, clientType = "browser", storage } = config;
    clientInstance = new AllauthClient(baseUrl, csrfTokenEndpoint, clientType, storage || getStorage(clientType, baseUrl));
  }
  return clientInstance;
}
function getClient() {
  if (!clientInstance) {
    throw new Error("AllauthClient not initialized. Please wrap your app with AllauthProvider or call initializeClient first.");
  }
  return clientInstance;
}

// lib/provider/AllauthProvider.tsx
function createDefaultQueryClient() {
  return new import_react_query.QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 1000 * 60 * 5,
        gcTime: 1000 * 60 * 10,
        retry: (failureCount, error) => {
          if (error?.status >= 400 && error?.status < 500 && error?.status !== 408 && error?.status !== 429) {
            return false;
          }
          return failureCount < 3;
        },
        refetchOnWindowFocus: false,
        refetchOnReconnect: true
      },
      mutations: {
        retry: false
      }
    }
  });
}
function AllauthProvider({
  clientType = "browser",
  baseUrl = "",
  csrfTokenEndpoint,
  storage,
  queryClient,
  children
}) {
  import_react.useMemo(() => {
    initializeClient({
      baseUrl,
      csrfTokenEndpoint,
      clientType,
      storage
    });
  }, [baseUrl, csrfTokenEndpoint, clientType, storage]);
  const finalQueryClient = import_react.useMemo(() => {
    return queryClient || createDefaultQueryClient();
  }, [queryClient]);
  return import_react.default.createElement(import_react_query.QueryClientProvider, { client: finalQueryClient }, children);
}
// lib/hooks/useAuth.ts
var import_react2 = require("react");

// lib/hooks/authentication/current-session/useAuthStatus.ts
var import_react_query2 = require("@tanstack/react-query");

// lib/queryKeys.ts
var allauthQueryKeys = {
  all: ["allauth"],
  config: () => [...allauthQueryKeys.all, "config"],
  auth: () => [...allauthQueryKeys.all, "auth"],
  authStatus: () => [...allauthQueryKeys.auth(), "status"],
  emails: () => [...allauthQueryKeys.all, "emails"],
  emailAddresses: () => [...allauthQueryKeys.all, "emails"],
  emailVerificationInfo: (key) => [...allauthQueryKeys.emails(), "verify", key],
  phone: () => [...allauthQueryKeys.all, "phone"],
  phoneNumber: () => [...allauthQueryKeys.all, "phone"],
  passwordReset: () => [...allauthQueryKeys.all, "password-reset"],
  passwordResetInfo: (key) => [...allauthQueryKeys.passwordReset(), key],
  providers: () => [...allauthQueryKeys.all, "providers"],
  providerAccounts: () => [...allauthQueryKeys.all, "providers"],
  providerSignup: () => [...allauthQueryKeys.providers(), "signup"],
  authenticators: () => [...allauthQueryKeys.all, "authenticators"],
  totp: () => [...allauthQueryKeys.authenticators(), "totp"],
  recoveryCodes: () => [...allauthQueryKeys.authenticators(), "recovery-codes"],
  webauthn: () => [...allauthQueryKeys.authenticators(), "webauthn"],
  sessions: () => [...allauthQueryKeys.all, "sessions"]
};
function getAuthInvalidationKeys() {
  return [
    allauthQueryKeys.auth(),
    allauthQueryKeys.emails(),
    allauthQueryKeys.providers(),
    allauthQueryKeys.authenticators(),
    allauthQueryKeys.sessions()
  ];
}
function getAllInvalidationKeys() {
  return [allauthQueryKeys.all];
}

// lib/hooks/authentication/current-session/useAuthStatus.ts
function useAuthStatus() {
  const client = getClient();
  return import_react_query2.useQuery({
    queryKey: allauthQueryKeys.authStatus(),
    queryFn: () => client.getAuthenticationStatus()
  });
}

// lib/hooks/authentication/current-session/useLogout.ts
var import_react_query3 = require("@tanstack/react-query");
function useLogout() {
  const client = getClient();
  const queryClient = import_react_query3.useQueryClient();
  return import_react_query3.useMutation({
    mutationFn: () => client.logout(),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
      queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
    }
  });
}

// lib/hooks/authentication/account/useLogin.ts
var import_react_query4 = require("@tanstack/react-query");
function useLogin() {
  const client = getClient();
  const queryClient = import_react_query4.useQueryClient();
  return import_react_query4.useMutation({
    mutationFn: (data) => client.login(data),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
      }
    }
  });
}

// lib/hooks/authentication/account/useSignup.ts
var import_react_query5 = require("@tanstack/react-query");
function useSignup() {
  const client = getClient();
  const queryClient = import_react_query5.useQueryClient();
  return import_react_query5.useMutation({
    mutationFn: (data) => client.signup(data),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
      }
    }
  });
}

// lib/hooks/useAuth.ts
function useAuth() {
  const authQuery = useAuthStatus();
  const loginMutation = useLogin();
  const logoutMutation = useLogout();
  const signupMutation = useSignup();
  const user = import_react2.useMemo(() => {
    if (authQuery.data && authQuery.data.status === 200) {
      return authQuery.data.data.user;
    }
    return null;
  }, [authQuery.data]);
  const isAuthenticated = import_react2.useMemo(() => {
    return authQuery.data?.status === 200 && authQuery.data.meta.is_authenticated;
  }, [authQuery.data]);
  const login = async (credentials) => {
    const result = await loginMutation.mutateAsync(credentials);
  };
  const logout = async () => {
    await logoutMutation.mutateAsync();
  };
  const signup = async (credentials) => {
    const result = await signupMutation.mutateAsync(credentials);
  };
  return {
    user,
    isAuthenticated,
    isLoading: authQuery.isLoading,
    error: authQuery.error,
    login,
    logout,
    signup,
    isLoggingIn: loginMutation.isPending,
    isLoggingOut: logoutMutation.isPending,
    isSigningUp: signupMutation.isPending,
    loginError: loginMutation.error,
    logoutError: logoutMutation.error,
    signupError: signupMutation.error,
    refetch: authQuery.refetch
  };
}
// lib/hooks/useEmailManagement.ts
var import_react3 = require("react");

// lib/hooks/account/email/useEmailAddresses.ts
var import_react_query6 = require("@tanstack/react-query");
function useEmailAddresses() {
  const client = getClient();
  return import_react_query6.useQuery({
    queryKey: allauthQueryKeys.emailAddresses(),
    queryFn: () => client.listEmailAddresses()
  });
}

// lib/hooks/account/email/useAddEmailAddress.ts
var import_react_query7 = require("@tanstack/react-query");
function useAddEmailAddress() {
  const client = getClient();
  const queryClient = import_react_query7.useQueryClient();
  return import_react_query7.useMutation({
    mutationFn: (data) => client.addEmailAddress(data),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.emailAddresses(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.emailAddresses() });
    }
  });
}

// lib/hooks/account/email/useRemoveEmailAddress.ts
var import_react_query8 = require("@tanstack/react-query");
function useRemoveEmailAddress() {
  const client = getClient();
  const queryClient = import_react_query8.useQueryClient();
  return import_react_query8.useMutation({
    mutationFn: (data) => client.removeEmailAddress(data),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.emailAddresses(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.emailAddresses() });
    }
  });
}

// lib/hooks/account/email/useSetPrimaryEmail.ts
var import_react_query9 = require("@tanstack/react-query");
function useSetPrimaryEmail() {
  const client = getClient();
  const queryClient = import_react_query9.useQueryClient();
  return import_react_query9.useMutation({
    mutationFn: (data) => client.changePrimaryEmailAddress(data),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.emailAddresses(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.emailAddresses() });
    }
  });
}

// lib/hooks/account/email/useRequestEmailVerification.ts
var import_react_query10 = require("@tanstack/react-query");
function useRequestEmailVerification() {
  const client = getClient();
  const queryClient = import_react_query10.useQueryClient();
  return import_react_query10.useMutation({
    mutationFn: (data) => client.requestEmailVerification(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.emailAddresses() });
    }
  });
}

// lib/hooks/authentication/account/useVerifyEmail.ts
var import_react_query11 = require("@tanstack/react-query");
function useVerifyEmail() {
  const client = getClient();
  const queryClient = import_react_query11.useQueryClient();
  return import_react_query11.useMutation({
    mutationFn: (data) => client.verifyEmail(data),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
      }
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.emailAddresses() });
    }
  });
}

// lib/hooks/authentication/account/useResendEmailVerification.ts
var import_react_query12 = require("@tanstack/react-query");
function useResendEmailVerification() {
  const client = getClient();
  return import_react_query12.useMutation({
    mutationFn: () => client.resendEmailVerification()
  });
}

// lib/hooks/authentication/account/useEmailVerificationInfo.ts
async function getEmailVerificationInfo(key) {
  const client = getClient();
  return client.getEmailVerificationInfo(key);
}

// lib/hooks/useEmailManagement.ts
function useEmailManagement() {
  const emailsQuery = useEmailAddresses();
  const addMutation = useAddEmailAddress();
  const removeMutation = useRemoveEmailAddress();
  const setPrimaryMutation = useSetPrimaryEmail();
  const requestVerificationMutation = useRequestEmailVerification();
  const verifyMutation = useVerifyEmail();
  const resendMutation = useResendEmailVerification();
  const emails = emailsQuery.data?.data || [];
  const primaryEmail = import_react3.useMemo(() => {
    const primary = emails.find((e) => e.primary);
    return primary?.email || null;
  }, [emails]);
  const verifiedEmails = import_react3.useMemo(() => {
    return emails.filter((e) => e.verified).map((e) => e.email);
  }, [emails]);
  const unverifiedEmails = import_react3.useMemo(() => {
    return emails.filter((e) => !e.verified).map((e) => e.email);
  }, [emails]);
  const addEmail = async (email) => {
    await addMutation.mutateAsync({ email });
  };
  const removeEmail = async (email) => {
    await removeMutation.mutateAsync({ email });
  };
  const setPrimary = async (email) => {
    await setPrimaryMutation.mutateAsync({ email, primary: true });
  };
  const requestVerification = async (email) => {
    await requestVerificationMutation.mutateAsync({ email });
  };
  const verifyEmail = async (key) => {
    await verifyMutation.mutateAsync({ key });
  };
  const resendVerification = async () => {
    await resendMutation.mutateAsync();
  };
  return {
    emails,
    primaryEmail,
    verifiedEmails,
    unverifiedEmails,
    isLoading: emailsQuery.isLoading,
    error: emailsQuery.error,
    addEmail,
    removeEmail,
    setPrimary,
    requestVerification,
    verifyEmail,
    resendVerification,
    getVerificationInfo: getEmailVerificationInfo,
    isAdding: addMutation.isPending,
    isRemoving: removeMutation.isPending,
    isSettingPrimary: setPrimaryMutation.isPending,
    isRequestingVerification: requestVerificationMutation.isPending,
    isVerifying: verifyMutation.isPending,
    isResending: resendMutation.isPending,
    refetch: emailsQuery.refetch
  };
}
// lib/hooks/authentication/password-reset/useRequestPasswordReset.ts
var import_react_query13 = require("@tanstack/react-query");
function useRequestPasswordReset() {
  const client = getClient();
  return import_react_query13.useMutation({
    mutationFn: (data) => client.requestPassword(data)
  });
}

// lib/hooks/authentication/password-reset/useResetPassword.ts
var import_react_query14 = require("@tanstack/react-query");
function useResetPassword() {
  const client = getClient();
  const queryClient = import_react_query14.useQueryClient();
  return import_react_query14.useMutation({
    mutationFn: (data) => client.resetPassword(data),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authStatus() });
      }
    }
  });
}

// lib/hooks/authentication/password-reset/usePasswordResetInfo.ts
async function getPasswordResetInfo(key) {
  const client = getClient();
  return client.getPasswordResetInfo(key);
}

// lib/hooks/usePasswordReset.ts
function usePasswordReset() {
  const requestMutation = useRequestPasswordReset();
  const confirmMutation = useResetPassword();
  const requestReset = async (email) => {
    await requestMutation.mutateAsync({ email });
  };
  const confirmReset = async (key, password) => {
    await confirmMutation.mutateAsync({ key, password });
  };
  return {
    requestReset,
    confirmReset,
    getResetInfo: getPasswordResetInfo,
    isRequesting: requestMutation.isPending,
    isConfirming: confirmMutation.isPending,
    requestError: requestMutation.error,
    confirmError: confirmMutation.error
  };
}
// lib/hooks/account/providers/useProviderAccounts.ts
var import_react_query15 = require("@tanstack/react-query");
function useProviderAccounts() {
  const client = getClient();
  return import_react_query15.useQuery({
    queryKey: allauthQueryKeys.providerAccounts(),
    queryFn: () => client.listProviderAccounts()
  });
}

// lib/hooks/account/providers/useDisconnectProvider.ts
var import_react_query16 = require("@tanstack/react-query");
function useDisconnectProvider() {
  const client = getClient();
  const queryClient = import_react_query16.useQueryClient();
  return import_react_query16.useMutation({
    mutationFn: (data) => client.disconnectProviderAccount(data),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.providerAccounts(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.providerAccounts() });
    }
  });
}

// lib/hooks/authentication/providers/useProviderRedirect.ts
function useProviderRedirect() {
  const client = getClient();
  return async (provider, callbackUrl, process = "login") => {
    return client.providerRedirect(provider, callbackUrl, process);
  };
}

// lib/hooks/authentication/providers/useProviderToken.ts
var import_react_query17 = require("@tanstack/react-query");
function useProviderToken() {
  const client = getClient();
  const queryClient = import_react_query17.useQueryClient();
  return import_react_query17.useMutation({
    mutationFn: (data) => client.providerToken(data),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
      }
    }
  });
}

// lib/hooks/useSocialAuth.ts
function useSocialAuth() {
  const accountsQuery = useProviderAccounts();
  const disconnectMutation = useDisconnectProvider();
  const redirectFn = useProviderRedirect();
  const tokenMutation = useProviderToken();
  const connectedProviders = accountsQuery.data?.data || [];
  const hasProvider = (provider) => {
    return connectedProviders.some((p) => p.provider.id === provider);
  };
  const connect = async (provider, callbackUrl) => {
    await redirectFn(provider, callbackUrl, "login");
  };
  const disconnect = async (provider, uid) => {
    await disconnectMutation.mutateAsync({ provider, account: uid });
  };
  const authenticateWithToken = async (data) => {
    await tokenMutation.mutateAsync(data);
  };
  return {
    connectedProviders,
    hasProvider,
    isLoading: accountsQuery.isLoading,
    error: accountsQuery.error,
    connect,
    disconnect,
    authenticateWithToken,
    isConnecting: false,
    isDisconnecting: disconnectMutation.isPending,
    isAuthenticating: tokenMutation.isPending,
    disconnectError: disconnectMutation.error,
    tokenError: tokenMutation.error,
    refetch: accountsQuery.refetch
  };
}
// lib/hooks/authentication/account/useReauthenticate.ts
var import_react_query18 = require("@tanstack/react-query");
function useReauthenticate() {
  const client = getClient();
  const queryClient = import_react_query18.useQueryClient();
  return import_react_query18.useMutation({
    mutationFn: (data) => client.reauthenticate(data),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authStatus() });
    }
  });
}
// lib/hooks/authentication/account/useVerifyPhone.ts
var import_react_query19 = require("@tanstack/react-query");
function useVerifyPhone() {
  const client = getClient();
  const queryClient = import_react_query19.useQueryClient();
  return import_react_query19.useMutation({
    mutationFn: (data) => client.verifyPhone(data),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
      }
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.phoneNumber() });
    }
  });
}
// lib/hooks/authentication/account/useResendPhoneVerification.ts
var import_react_query20 = require("@tanstack/react-query");
function useResendPhoneVerification() {
  const client = getClient();
  return import_react_query20.useMutation({
    mutationFn: () => client.resendPhoneVerification()
  });
}
// lib/hooks/authentication/login-by-code/useRequestLoginCode.ts
var import_react_query21 = require("@tanstack/react-query");
function useRequestLoginCode() {
  const client = getClient();
  return import_react_query21.useMutation({
    mutationFn: (data) => client.requestLoginCode(data)
  });
}
// lib/hooks/authentication/login-by-code/useConfirmLoginCode.ts
var import_react_query22 = require("@tanstack/react-query");
function useConfirmLoginCode() {
  const client = getClient();
  const queryClient = import_react_query22.useQueryClient();
  return import_react_query22.useMutation({
    mutationFn: (data) => client.confirmLoginCode(data),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
      }
    }
  });
}
// lib/hooks/authentication/providers/useProviderSignupData.ts
var import_react_query23 = require("@tanstack/react-query");
function useProviderSignupData() {
  const client = getClient();
  return import_react_query23.useQuery({
    queryKey: allauthQueryKeys.providerSignup(),
    queryFn: () => client.getProviderSignup(),
    enabled: false
  });
}
// lib/hooks/authentication/providers/useProviderSignup.ts
var import_react_query24 = require("@tanstack/react-query");
function useProviderSignup() {
  const client = getClient();
  const queryClient = import_react_query24.useQueryClient();
  return import_react_query24.useMutation({
    mutationFn: (data) => client.providerSignup(data),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
      }
    }
  });
}
// lib/hooks/authentication/two-factor/useMfaAuthenticate.ts
var import_react_query25 = require("@tanstack/react-query");
function useMfaAuthenticate() {
  const client = getClient();
  const queryClient = import_react_query25.useQueryClient();
  return import_react_query25.useMutation({
    mutationFn: (data) => client.mfaAuthenticate(data),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
      }
    }
  });
}
// lib/hooks/authentication/two-factor/useMfaReauthenticate.ts
var import_react_query26 = require("@tanstack/react-query");
function useMfaReauthenticate() {
  const client = getClient();
  const queryClient = import_react_query26.useQueryClient();
  return import_react_query26.useMutation({
    mutationFn: () => client.mfaReauthenticate(),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authStatus() });
    }
  });
}
// lib/hooks/authentication/two-factor/useMfaTrust.ts
var import_react_query27 = require("@tanstack/react-query");
function useMfaTrust() {
  const client = getClient();
  const queryClient = import_react_query27.useQueryClient();
  return import_react_query27.useMutation({
    mutationFn: (data) => client.mfaTrust(data),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authStatus() });
    }
  });
}
// lib/hooks/authentication/webauthn/useWebAuthnSignupOptions.ts
async function getWebAuthnSignupOptions() {
  const client = getClient();
  return client.getWebAuthnSignupOptions();
}
// lib/hooks/authentication/webauthn/useWebAuthnSignup.ts
var import_react_query28 = require("@tanstack/react-query");
function useWebAuthnSignup() {
  const client = getClient();
  const queryClient = import_react_query28.useQueryClient();
  return import_react_query28.useMutation({
    mutationFn: (data) => client.webAuthnSignup(data),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
      }
    }
  });
}
// lib/hooks/authentication/webauthn/useWebAuthnLoginOptions.ts
async function getWebAuthnLoginOptions() {
  const client = getClient();
  return client.getWebAuthnLoginOptions();
}
// lib/hooks/authentication/webauthn/useWebAuthnLogin.ts
var import_react_query29 = require("@tanstack/react-query");
function useWebAuthnLogin() {
  const client = getClient();
  const queryClient = import_react_query29.useQueryClient();
  return import_react_query29.useMutation({
    mutationFn: (data) => client.webAuthnLogin(data),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
      }
    }
  });
}
// lib/hooks/authentication/webauthn/useWebAuthnAuthenticateOptions.ts
async function getWebAuthnAuthenticateOptions() {
  const client = getClient();
  return client.getWebAuthnAuthenticateOptions();
}
// lib/hooks/authentication/webauthn/useWebAuthnAuthenticate.ts
var import_react_query30 = require("@tanstack/react-query");
function useWebAuthnAuthenticate() {
  const client = getClient();
  const queryClient = import_react_query30.useQueryClient();
  return import_react_query30.useMutation({
    mutationFn: (credential) => client.webAuthnAuthenticate(credential),
    onSuccess: (data) => {
      if (data.status === 200) {
        queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
        queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
      }
    }
  });
}
// lib/hooks/authentication/webauthn/useWebAuthnReauthenticateOptions.ts
async function getWebAuthnReauthenticateOptions() {
  const client = getClient();
  return client.getWebAuthnReauthenticateOptions();
}
// lib/hooks/authentication/webauthn/useWebAuthnReauthenticate.ts
var import_react_query31 = require("@tanstack/react-query");
function useWebAuthnReauthenticate() {
  const client = getClient();
  const queryClient = import_react_query31.useQueryClient();
  return import_react_query31.useMutation({
    mutationFn: (credential) => client.webAuthnReauthenticate(credential),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authStatus() });
    }
  });
}
// lib/hooks/account/phone/usePhoneNumber.ts
var import_react_query32 = require("@tanstack/react-query");
function usePhoneNumber() {
  const client = getClient();
  return import_react_query32.useQuery({
    queryKey: allauthQueryKeys.phoneNumber(),
    queryFn: () => client.getPhoneNumber()
  });
}
// lib/hooks/account/phone/useUpdatePhoneNumber.ts
var import_react_query33 = require("@tanstack/react-query");
function useUpdatePhoneNumber() {
  const client = getClient();
  const queryClient = import_react_query33.useQueryClient();
  return import_react_query33.useMutation({
    mutationFn: (phone) => client.updatePhoneNumber(phone),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.phoneNumber(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.phoneNumber() });
    }
  });
}
// lib/hooks/account/phone/useRemovePhoneNumber.ts
var import_react_query34 = require("@tanstack/react-query");
function useRemovePhoneNumber() {
  const client = getClient();
  const queryClient = import_react_query34.useQueryClient();
  return import_react_query34.useMutation({
    mutationFn: () => client.removePhoneNumber(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.phoneNumber() });
    }
  });
}
// lib/hooks/account/password/useChangePassword.ts
var import_react_query35 = require("@tanstack/react-query");
function useChangePassword() {
  const client = getClient();
  return import_react_query35.useMutation({
    mutationFn: (data) => client.changePassword(data)
  });
}
// lib/hooks/account/authenticators/useAuthenticators.ts
var import_react_query36 = require("@tanstack/react-query");
function useAuthenticators() {
  const client = getClient();
  return import_react_query36.useQuery({
    queryKey: allauthQueryKeys.authenticators(),
    queryFn: () => client.listAuthenticators()
  });
}
// lib/hooks/account/authenticators/totp/useTOTPAuthenticator.ts
async function getTOTPAuthenticator() {
  const client = getClient();
  return client.getTOTPAuthenticator();
}
// lib/hooks/account/authenticators/totp/useActivateTOTP.ts
var import_react_query37 = require("@tanstack/react-query");
function useActivateTOTP() {
  const client = getClient();
  const queryClient = import_react_query37.useQueryClient();
  return import_react_query37.useMutation({
    mutationFn: (data) => client.activateTOTP(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authenticators() });
    }
  });
}
// lib/hooks/account/authenticators/totp/useDeactivateTOTP.ts
var import_react_query38 = require("@tanstack/react-query");
function useDeactivateTOTP() {
  const client = getClient();
  const queryClient = import_react_query38.useQueryClient();
  return import_react_query38.useMutation({
    mutationFn: () => client.deactivateTOTP(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authenticators() });
    }
  });
}
// lib/hooks/account/authenticators/recovery-codes/useRecoveryCodes.ts
async function getRecoveryCodes() {
  const client = getClient();
  return client.listRecoveryCodes();
}
// lib/hooks/account/authenticators/recovery-codes/useRegenerateRecoveryCodes.ts
var import_react_query39 = require("@tanstack/react-query");
function useRegenerateRecoveryCodes() {
  const client = getClient();
  const queryClient = import_react_query39.useQueryClient();
  return import_react_query39.useMutation({
    mutationFn: () => client.regenerateRecoveryCodes(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authenticators() });
    }
  });
}
// lib/hooks/account/authenticators/webauthn/useWebAuthnCredentials.ts
var import_react_query40 = require("@tanstack/react-query");
function useWebAuthnCredentials() {
  const client = getClient();
  return import_react_query40.useQuery({
    queryKey: allauthQueryKeys.webauthn(),
    queryFn: () => client.listWebAuthnCredentials()
  });
}
// lib/hooks/account/authenticators/webauthn/useDeleteWebAuthnCredential.ts
var import_react_query41 = require("@tanstack/react-query");
function useDeleteWebAuthnCredential() {
  const client = getClient();
  const queryClient = import_react_query41.useQueryClient();
  return import_react_query41.useMutation({
    mutationFn: (id) => client.deleteWebAuthnCredential(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.webauthn() });
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authenticators() });
    }
  });
}
// lib/hooks/sessions/useListSessions.ts
var import_react_query42 = require("@tanstack/react-query");
function useListSessions() {
  const client = getClient();
  return import_react_query42.useQuery({
    queryKey: allauthQueryKeys.sessions(),
    queryFn: () => client.listSessions()
  });
}
// lib/hooks/sessions/useDeleteSession.ts
var import_react_query43 = require("@tanstack/react-query");
function useDeleteSession() {
  const client = getClient();
  const queryClient = import_react_query43.useQueryClient();
  const { clearTokens } = useAuthTokens();
  return import_react_query43.useMutation({
    mutationFn: (id) => client.deleteSession(id),
    onSuccess: (data, variables) => {
      if (!variables) {
        clearTokens();
        queryClient.setQueryData(allauthQueryKeys.authStatus(), {
          status: 401,
          data: { flows: [] },
          meta: { is_authenticated: false }
        });
        queryClient.invalidateQueries({ queryKey: allauthQueryKeys.all });
      } else {
        queryClient.setQueryData(allauthQueryKeys.sessions(), data);
        queryClient.invalidateQueries({ queryKey: allauthQueryKeys.sessions() });
      }
    }
  });
}
// lib/hooks/config/useConfig.ts
var import_react_query44 = require("@tanstack/react-query");
function useConfig() {
  const client = getClient();
  return import_react_query44.useQuery({
    queryKey: allauthQueryKeys.config(),
    queryFn: () => client.getConfiguration(),
    staleTime: 1000 * 60 * 60
  });
}
