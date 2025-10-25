import type { EmailAddress } from '../api/types';
export interface UseEmailManagementResult {
    emails: EmailAddress[];
    primaryEmail: string | null;
    verifiedEmails: string[];
    unverifiedEmails: string[];
    isLoading: boolean;
    error: any;
    addEmail: (email: string) => Promise<void>;
    removeEmail: (email: string) => Promise<void>;
    setPrimary: (email: string) => Promise<void>;
    requestVerification: (email: string) => Promise<void>;
    verifyEmail: (key: string) => Promise<void>;
    resendVerification: () => Promise<void>;
    getVerificationInfo: (key: string) => Promise<any>;
    isAdding: boolean;
    isRemoving: boolean;
    isSettingPrimary: boolean;
    isRequestingVerification: boolean;
    isVerifying: boolean;
    isResending: boolean;
    refetch: () => void;
}
/**
 * High-level hook for complete email address management.
 * Combines all email-related queries and mutations into a single interface.
 *
 * @example
 * ```tsx
 * const { emails, primaryEmail, addEmail, setPrimary } = useEmailManagement();
 *
 * // Add new email
 * await addEmail('new@example.com');
 *
 * // Make it primary
 * await setPrimary('new@example.com');
 * ```
 */
export declare function useEmailManagement(): UseEmailManagementResult;
//# sourceMappingURL=useEmailManagement.d.ts.map