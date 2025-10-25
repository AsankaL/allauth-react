/**
 * Query keys factory for all allauth-related queries.
 * This provides a centralized, hierarchical structure for cache management.
 */
export declare const allauthQueryKeys: {
    readonly all: readonly ["allauth"];
    readonly config: () => readonly ["allauth", "config"];
    readonly auth: () => readonly ["allauth", "auth"];
    readonly authStatus: () => readonly ["allauth", "auth", "status"];
    readonly emails: () => readonly ["allauth", "emails"];
    readonly emailAddresses: () => readonly ["allauth", "emails"];
    readonly emailVerificationInfo: (key: string) => readonly ["allauth", "emails", "verify", string];
    readonly phone: () => readonly ["allauth", "phone"];
    readonly phoneNumber: () => readonly ["allauth", "phone"];
    readonly passwordReset: () => readonly ["allauth", "password-reset"];
    readonly passwordResetInfo: (key: string) => readonly ["allauth", "password-reset", string];
    readonly providers: () => readonly ["allauth", "providers"];
    readonly providerAccounts: () => readonly ["allauth", "providers"];
    readonly providerSignup: () => readonly ["allauth", "providers", "signup"];
    readonly authenticators: () => readonly ["allauth", "authenticators"];
    readonly totp: () => readonly ["allauth", "authenticators", "totp"];
    readonly recoveryCodes: () => readonly ["allauth", "authenticators", "recovery-codes"];
    readonly webauthn: () => readonly ["allauth", "authenticators", "webauthn"];
    readonly sessions: () => readonly ["allauth", "sessions"];
};
/**
 * Helper function to invalidate all queries related to authentication
 */
export declare function getAuthInvalidationKeys(): readonly (readonly string[])[];
/**
 * Helper function to invalidate all queries
 */
export declare function getAllInvalidationKeys(): readonly (readonly string[])[];
//# sourceMappingURL=queryKeys.d.ts.map