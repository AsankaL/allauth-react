// lib/provider/AllauthProvider.tsx
import React, { useMemo } from "react";
import {
  QueryClient,
  QueryClientProvider
} from "@tanstack/react-query";

// lib/api/storage.ts
import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
var useAuthTokenStore = create()(persist((set) => ({
  sessionToken: null,
  csrfToken: null,
  setSessionToken: (token) => set({ sessionToken: token }),
  setCSRFToken: (token) => set({ csrfToken: token }),
  clearTokens: () => set({ sessionToken: null, csrfToken: null })
}), {
  name: "allauth-tokens",
  storage: createJSONStorage(() => localStorage),
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
  return new QueryClient({
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
  useMemo(() => {
    initializeClient({
      baseUrl,
      csrfTokenEndpoint,
      clientType,
      storage
    });
  }, [baseUrl, csrfTokenEndpoint, clientType, storage]);
  const finalQueryClient = useMemo(() => {
    return queryClient || createDefaultQueryClient();
  }, [queryClient]);
  return React.createElement(QueryClientProvider, { client: finalQueryClient }, children);
}
// lib/hooks/useAuth.ts
import { useMemo as useMemo2 } from "react";

// lib/hooks/authentication/current-session/useAuthStatus.ts
import { useQuery } from "@tanstack/react-query";

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
  return useQuery({
    queryKey: allauthQueryKeys.authStatus(),
    queryFn: () => client.getAuthenticationStatus()
  });
}

// lib/hooks/authentication/current-session/useLogout.ts
import { useMutation, useQueryClient } from "@tanstack/react-query";
function useLogout() {
  const client = getClient();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => client.logout(),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
      queryClient.invalidateQueries({ queryKey: getAuthInvalidationKeys() });
    }
  });
}

// lib/hooks/authentication/account/useLogin.ts
import { useMutation as useMutation2, useQueryClient as useQueryClient2 } from "@tanstack/react-query";
function useLogin() {
  const client = getClient();
  const queryClient = useQueryClient2();
  return useMutation2({
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
import { useMutation as useMutation3, useQueryClient as useQueryClient3 } from "@tanstack/react-query";
function useSignup() {
  const client = getClient();
  const queryClient = useQueryClient3();
  return useMutation3({
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
  const user = useMemo2(() => {
    if (authQuery.data && authQuery.data.status === 200) {
      return authQuery.data.data.user;
    }
    return null;
  }, [authQuery.data]);
  const isAuthenticated = useMemo2(() => {
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
import { useMemo as useMemo3 } from "react";

// lib/hooks/account/email/useEmailAddresses.ts
import { useQuery as useQuery2 } from "@tanstack/react-query";
function useEmailAddresses() {
  const client = getClient();
  return useQuery2({
    queryKey: allauthQueryKeys.emailAddresses(),
    queryFn: () => client.listEmailAddresses()
  });
}

// lib/hooks/account/email/useAddEmailAddress.ts
import { useMutation as useMutation4, useQueryClient as useQueryClient4 } from "@tanstack/react-query";
function useAddEmailAddress() {
  const client = getClient();
  const queryClient = useQueryClient4();
  return useMutation4({
    mutationFn: (data) => client.addEmailAddress(data),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.emailAddresses(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.emailAddresses() });
    }
  });
}

// lib/hooks/account/email/useRemoveEmailAddress.ts
import { useMutation as useMutation5, useQueryClient as useQueryClient5 } from "@tanstack/react-query";
function useRemoveEmailAddress() {
  const client = getClient();
  const queryClient = useQueryClient5();
  return useMutation5({
    mutationFn: (data) => client.removeEmailAddress(data),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.emailAddresses(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.emailAddresses() });
    }
  });
}

// lib/hooks/account/email/useSetPrimaryEmail.ts
import { useMutation as useMutation6, useQueryClient as useQueryClient6 } from "@tanstack/react-query";
function useSetPrimaryEmail() {
  const client = getClient();
  const queryClient = useQueryClient6();
  return useMutation6({
    mutationFn: (data) => client.changePrimaryEmailAddress(data),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.emailAddresses(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.emailAddresses() });
    }
  });
}

// lib/hooks/account/email/useRequestEmailVerification.ts
import { useMutation as useMutation7, useQueryClient as useQueryClient7 } from "@tanstack/react-query";
function useRequestEmailVerification() {
  const client = getClient();
  const queryClient = useQueryClient7();
  return useMutation7({
    mutationFn: (data) => client.requestEmailVerification(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.emailAddresses() });
    }
  });
}

// lib/hooks/authentication/account/useVerifyEmail.ts
import { useMutation as useMutation8, useQueryClient as useQueryClient8 } from "@tanstack/react-query";
function useVerifyEmail() {
  const client = getClient();
  const queryClient = useQueryClient8();
  return useMutation8({
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
import { useMutation as useMutation9 } from "@tanstack/react-query";
function useResendEmailVerification() {
  const client = getClient();
  return useMutation9({
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
  const primaryEmail = useMemo3(() => {
    const primary = emails.find((e) => e.primary);
    return primary?.email || null;
  }, [emails]);
  const verifiedEmails = useMemo3(() => {
    return emails.filter((e) => e.verified).map((e) => e.email);
  }, [emails]);
  const unverifiedEmails = useMemo3(() => {
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
import { useMutation as useMutation10 } from "@tanstack/react-query";
function useRequestPasswordReset() {
  const client = getClient();
  return useMutation10({
    mutationFn: (data) => client.requestPassword(data)
  });
}

// lib/hooks/authentication/password-reset/useResetPassword.ts
import { useMutation as useMutation11, useQueryClient as useQueryClient9 } from "@tanstack/react-query";
function useResetPassword() {
  const client = getClient();
  const queryClient = useQueryClient9();
  return useMutation11({
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
import { useQuery as useQuery3 } from "@tanstack/react-query";
function useProviderAccounts() {
  const client = getClient();
  return useQuery3({
    queryKey: allauthQueryKeys.providerAccounts(),
    queryFn: () => client.listProviderAccounts()
  });
}

// lib/hooks/account/providers/useDisconnectProvider.ts
import { useMutation as useMutation12, useQueryClient as useQueryClient10 } from "@tanstack/react-query";
function useDisconnectProvider() {
  const client = getClient();
  const queryClient = useQueryClient10();
  return useMutation12({
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
import { useMutation as useMutation13, useQueryClient as useQueryClient11 } from "@tanstack/react-query";
function useProviderToken() {
  const client = getClient();
  const queryClient = useQueryClient11();
  return useMutation13({
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
import { useMutation as useMutation14, useQueryClient as useQueryClient12 } from "@tanstack/react-query";
function useReauthenticate() {
  const client = getClient();
  const queryClient = useQueryClient12();
  return useMutation14({
    mutationFn: (data) => client.reauthenticate(data),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authStatus() });
    }
  });
}
// lib/hooks/authentication/account/useVerifyPhone.ts
import { useMutation as useMutation15, useQueryClient as useQueryClient13 } from "@tanstack/react-query";
function useVerifyPhone() {
  const client = getClient();
  const queryClient = useQueryClient13();
  return useMutation15({
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
import { useMutation as useMutation16 } from "@tanstack/react-query";
function useResendPhoneVerification() {
  const client = getClient();
  return useMutation16({
    mutationFn: () => client.resendPhoneVerification()
  });
}
// lib/hooks/authentication/login-by-code/useRequestLoginCode.ts
import { useMutation as useMutation17 } from "@tanstack/react-query";
function useRequestLoginCode() {
  const client = getClient();
  return useMutation17({
    mutationFn: (data) => client.requestLoginCode(data)
  });
}
// lib/hooks/authentication/login-by-code/useConfirmLoginCode.ts
import { useMutation as useMutation18, useQueryClient as useQueryClient14 } from "@tanstack/react-query";
function useConfirmLoginCode() {
  const client = getClient();
  const queryClient = useQueryClient14();
  return useMutation18({
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
import { useQuery as useQuery4 } from "@tanstack/react-query";
function useProviderSignupData() {
  const client = getClient();
  return useQuery4({
    queryKey: allauthQueryKeys.providerSignup(),
    queryFn: () => client.getProviderSignup(),
    enabled: false
  });
}
// lib/hooks/authentication/providers/useProviderSignup.ts
import { useMutation as useMutation19, useQueryClient as useQueryClient15 } from "@tanstack/react-query";
function useProviderSignup() {
  const client = getClient();
  const queryClient = useQueryClient15();
  return useMutation19({
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
import { useMutation as useMutation20, useQueryClient as useQueryClient16 } from "@tanstack/react-query";
function useMfaAuthenticate() {
  const client = getClient();
  const queryClient = useQueryClient16();
  return useMutation20({
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
import { useMutation as useMutation21, useQueryClient as useQueryClient17 } from "@tanstack/react-query";
function useMfaReauthenticate() {
  const client = getClient();
  const queryClient = useQueryClient17();
  return useMutation21({
    mutationFn: () => client.mfaReauthenticate(),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authStatus() });
    }
  });
}
// lib/hooks/authentication/two-factor/useMfaTrust.ts
import { useMutation as useMutation22, useQueryClient as useQueryClient18 } from "@tanstack/react-query";
function useMfaTrust() {
  const client = getClient();
  const queryClient = useQueryClient18();
  return useMutation22({
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
import { useMutation as useMutation23, useQueryClient as useQueryClient19 } from "@tanstack/react-query";
function useWebAuthnSignup() {
  const client = getClient();
  const queryClient = useQueryClient19();
  return useMutation23({
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
import { useMutation as useMutation24, useQueryClient as useQueryClient20 } from "@tanstack/react-query";
function useWebAuthnLogin() {
  const client = getClient();
  const queryClient = useQueryClient20();
  return useMutation24({
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
import { useMutation as useMutation25, useQueryClient as useQueryClient21 } from "@tanstack/react-query";
function useWebAuthnAuthenticate() {
  const client = getClient();
  const queryClient = useQueryClient21();
  return useMutation25({
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
import { useMutation as useMutation26, useQueryClient as useQueryClient22 } from "@tanstack/react-query";
function useWebAuthnReauthenticate() {
  const client = getClient();
  const queryClient = useQueryClient22();
  return useMutation26({
    mutationFn: (credential) => client.webAuthnReauthenticate(credential),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.authStatus(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authStatus() });
    }
  });
}
// lib/hooks/account/phone/usePhoneNumber.ts
import { useQuery as useQuery5 } from "@tanstack/react-query";
function usePhoneNumber() {
  const client = getClient();
  return useQuery5({
    queryKey: allauthQueryKeys.phoneNumber(),
    queryFn: () => client.getPhoneNumber()
  });
}
// lib/hooks/account/phone/useUpdatePhoneNumber.ts
import { useMutation as useMutation27, useQueryClient as useQueryClient23 } from "@tanstack/react-query";
function useUpdatePhoneNumber() {
  const client = getClient();
  const queryClient = useQueryClient23();
  return useMutation27({
    mutationFn: (phone) => client.updatePhoneNumber(phone),
    onSuccess: (data) => {
      queryClient.setQueryData(allauthQueryKeys.phoneNumber(), data);
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.phoneNumber() });
    }
  });
}
// lib/hooks/account/phone/useRemovePhoneNumber.ts
import { useMutation as useMutation28, useQueryClient as useQueryClient24 } from "@tanstack/react-query";
function useRemovePhoneNumber() {
  const client = getClient();
  const queryClient = useQueryClient24();
  return useMutation28({
    mutationFn: () => client.removePhoneNumber(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.phoneNumber() });
    }
  });
}
// lib/hooks/account/password/useChangePassword.ts
import { useMutation as useMutation29 } from "@tanstack/react-query";
function useChangePassword() {
  const client = getClient();
  return useMutation29({
    mutationFn: (data) => client.changePassword(data)
  });
}
// lib/hooks/account/authenticators/useAuthenticators.ts
import { useQuery as useQuery6 } from "@tanstack/react-query";
function useAuthenticators() {
  const client = getClient();
  return useQuery6({
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
import { useMutation as useMutation30, useQueryClient as useQueryClient25 } from "@tanstack/react-query";
function useActivateTOTP() {
  const client = getClient();
  const queryClient = useQueryClient25();
  return useMutation30({
    mutationFn: (data) => client.activateTOTP(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authenticators() });
    }
  });
}
// lib/hooks/account/authenticators/totp/useDeactivateTOTP.ts
import { useMutation as useMutation31, useQueryClient as useQueryClient26 } from "@tanstack/react-query";
function useDeactivateTOTP() {
  const client = getClient();
  const queryClient = useQueryClient26();
  return useMutation31({
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
import { useMutation as useMutation32, useQueryClient as useQueryClient27 } from "@tanstack/react-query";
function useRegenerateRecoveryCodes() {
  const client = getClient();
  const queryClient = useQueryClient27();
  return useMutation32({
    mutationFn: () => client.regenerateRecoveryCodes(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authenticators() });
    }
  });
}
// lib/hooks/account/authenticators/webauthn/useWebAuthnCredentials.ts
import { useQuery as useQuery7 } from "@tanstack/react-query";
function useWebAuthnCredentials() {
  const client = getClient();
  return useQuery7({
    queryKey: allauthQueryKeys.webauthn(),
    queryFn: () => client.listWebAuthnCredentials()
  });
}
// lib/hooks/account/authenticators/webauthn/useDeleteWebAuthnCredential.ts
import { useMutation as useMutation33, useQueryClient as useQueryClient28 } from "@tanstack/react-query";
function useDeleteWebAuthnCredential() {
  const client = getClient();
  const queryClient = useQueryClient28();
  return useMutation33({
    mutationFn: (id) => client.deleteWebAuthnCredential(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.webauthn() });
      queryClient.invalidateQueries({ queryKey: allauthQueryKeys.authenticators() });
    }
  });
}
// lib/hooks/sessions/useListSessions.ts
import { useQuery as useQuery8 } from "@tanstack/react-query";
function useListSessions() {
  const client = getClient();
  return useQuery8({
    queryKey: allauthQueryKeys.sessions(),
    queryFn: () => client.listSessions()
  });
}
// lib/hooks/sessions/useDeleteSession.ts
import { useMutation as useMutation34, useQueryClient as useQueryClient29 } from "@tanstack/react-query";
function useDeleteSession() {
  const client = getClient();
  const queryClient = useQueryClient29();
  const { clearTokens } = useAuthTokens();
  return useMutation34({
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
import { useQuery as useQuery9 } from "@tanstack/react-query";
function useConfig() {
  const client = getClient();
  return useQuery9({
    queryKey: allauthQueryKeys.config(),
    queryFn: () => client.getConfiguration(),
    staleTime: 1000 * 60 * 60
  });
}
export {
  useWebAuthnSignup,
  useWebAuthnReauthenticate,
  useWebAuthnLogin,
  useWebAuthnCredentials,
  useWebAuthnAuthenticate,
  useVerifyPhone,
  useVerifyEmail,
  useUpdatePhoneNumber,
  useSocialAuth,
  useSignup,
  useSetPrimaryEmail,
  useResetPassword,
  useResendPhoneVerification,
  useResendEmailVerification,
  useRequestPasswordReset,
  useRequestLoginCode,
  useRequestEmailVerification,
  useRemovePhoneNumber,
  useRemoveEmailAddress,
  useRegenerateRecoveryCodes,
  useReauthenticate,
  useProviderToken,
  useProviderSignupData,
  useProviderSignup,
  useProviderRedirect,
  useProviderAccounts,
  usePhoneNumber,
  usePasswordReset,
  useMfaTrust,
  useMfaReauthenticate,
  useMfaAuthenticate,
  useLogout,
  useLogin,
  useListSessions,
  useEmailManagement,
  useEmailAddresses,
  useDisconnectProvider,
  useDeleteWebAuthnCredential,
  useDeleteSession,
  useDeactivateTOTP,
  useConfirmLoginCode,
  useConfig,
  useChangePassword,
  useAuthenticators,
  useAuthTokens,
  useAuthTokenStore,
  useAuthStatus,
  useAuth,
  useAddEmailAddress,
  useActivateTOTP,
  initializeClient,
  getWebAuthnSignupOptions,
  getWebAuthnReauthenticateOptions,
  getWebAuthnLoginOptions,
  getWebAuthnAuthenticateOptions,
  getTOTPAuthenticator,
  getStorage,
  getRecoveryCodes,
  getPasswordResetInfo,
  getEmailVerificationInfo,
  getClient,
  getAuthInvalidationKeys,
  getAllInvalidationKeys,
  allauthQueryKeys,
  ZustandStorage,
  HybridStorage,
  CookieStorage,
  AllauthProvider,
  AllauthClient
};
