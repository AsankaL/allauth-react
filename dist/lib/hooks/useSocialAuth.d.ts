import type { ProviderAccount, ProviderTokenRequest } from '../api/types';
export interface UseSocialAuthResult {
    connectedProviders: ProviderAccount[];
    hasProvider: (provider: string) => boolean;
    isLoading: boolean;
    error: any;
    connect: (provider: string, callbackUrl: string) => Promise<void>;
    disconnect: (provider: string, uid: string) => Promise<void>;
    authenticateWithToken: (data: ProviderTokenRequest) => Promise<void>;
    isConnecting: boolean;
    isDisconnecting: boolean;
    isAuthenticating: boolean;
    disconnectError: any;
    tokenError: any;
    refetch: () => void;
}
/**
 * High-level hook for social authentication provider management.
 * Handles OAuth flows, token authentication, and provider connections.
 *
 * @example
 * ```tsx
 * const { connectedProviders, connect, disconnect } = useSocialAuth();
 *
 * // Redirect-based OAuth flow
 * await connect('google', '/auth/callback');
 *
 * // Token-based authentication (for mobile apps)
 * await authenticateWithToken({
 *   provider: 'google',
 *   process: 'login',
 *   token: { id_token: '...' }
 * });
 *
 * // Disconnect a provider
 * const googleAccount = connectedProviders.find(p => p.provider.id === 'google');
 * if (googleAccount) {
 *   await disconnect('google', googleAccount.uid);
 * }
 * ```
 */
export declare function useSocialAuth(): UseSocialAuthResult;
//# sourceMappingURL=useSocialAuth.d.ts.map