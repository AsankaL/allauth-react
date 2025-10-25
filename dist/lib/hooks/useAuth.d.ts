import type { User, LoginRequest, SignupRequest } from '../api/types';
export interface UseAuthResult {
    user: User | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: any;
    login: (credentials: LoginRequest) => Promise<void>;
    logout: () => Promise<void>;
    signup: (credentials: SignupRequest) => Promise<void>;
    isLoggingIn: boolean;
    isLoggingOut: boolean;
    isSigningUp: boolean;
    loginError: any;
    logoutError: any;
    signupError: any;
    refetch: () => void;
}
/**
 * High-level authentication hook that combines auth status with common mutations.
 * Provides an intuitive API for authentication operations.
 *
 * @example
 * ```tsx
 * const { user, isAuthenticated, login, logout } = useAuth();
 *
 * if (!isAuthenticated) {
 *   return <LoginForm onSubmit={login} />;
 * }
 *
 * return <Dashboard user={user} onLogout={logout} />;
 * ```
 */
export declare function useAuth(): UseAuthResult;
//# sourceMappingURL=useAuth.d.ts.map