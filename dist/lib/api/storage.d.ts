import { type UseBoundStore, type StoreApi } from 'zustand';
import type { StorageInterface } from './types';
interface AuthTokenStore {
    sessionToken: string | null;
    csrfToken: string | null;
    setSessionToken: (token: string | null) => void;
    setCSRFToken: (token: string | null) => void;
    clearTokens: () => void;
}
declare const useAuthTokenStore: UseBoundStore<StoreApi<AuthTokenStore>>;
/**
 * Zustand-based storage for JWT/token-based authentication (mobile apps, SPAs)
 */
export declare class ZustandStorage implements StorageInterface {
    getSessionToken(): Promise<string | null>;
    setSessionToken(value: string | null): Promise<void>;
    getCSRFToken(): Promise<string | null>;
    setCSRFToken(value: string | null): Promise<void>;
}
/**
 * Cookie-based storage for traditional session authentication (SSR, browser)
 */
export declare class CookieStorage implements StorageInterface {
    private useSecure;
    private csrfTokenCookieName;
    private sessionTokenCookieName;
    constructor(options?: {
        apiUrl?: string;
        csrfTokenCookieName?: string;
        sessionTokenCookieName?: string;
    });
    getSessionToken(): Promise<string | null>;
    setSessionToken(value: string | null): Promise<void>;
    getCSRFToken(): Promise<string | null>;
    setCSRFToken(value: string | null): Promise<void>;
}
/**
 * Hybrid storage that uses Zustand for tokens but also checks cookies
 * This is useful for apps that need to work with both JWT and cookie-based auth
 */
export declare class HybridStorage implements StorageInterface {
    private zustandStorage;
    private cookieStorage;
    constructor(options?: {
        apiUrl?: string;
        csrfTokenCookieName?: string;
        sessionTokenCookieName?: string;
    });
    getSessionToken(): Promise<string | null>;
    setSessionToken(value: string | null): Promise<void>;
    getCSRFToken(): Promise<string | null>;
    setCSRFToken(value: string | null): Promise<void>;
}
export { useAuthTokenStore };
export declare function getCSRFToken(): string | undefined;
export declare function getSessionId(): string | undefined;
/**
 * Hook to access auth tokens reactively
 */
export declare function useAuthTokens(): {
    sessionToken: string | null;
    csrfToken: string | null;
    setSessionToken: (token: string | null) => void;
    setCSRFToken: (token: string | null) => void;
    clearTokens: () => void;
};
/**
 * Get the appropriate storage implementation based on client type
 */
export declare function getStorage(clientType: 'app' | 'browser', apiUrl?: string): StorageInterface;
//# sourceMappingURL=storage.d.ts.map