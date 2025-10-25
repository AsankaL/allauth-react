export interface UsePasswordResetResult {
    requestReset: (email: string) => Promise<void>;
    confirmReset: (key: string, password: string) => Promise<void>;
    getResetInfo: (key: string) => Promise<any>;
    isRequesting: boolean;
    isConfirming: boolean;
    requestError: any;
    confirmError: any;
}
/**
 * High-level hook for password reset flow.
 * Handles both requesting a reset and confirming with new password.
 *
 * @example
 * ```tsx
 * const { requestReset, confirmReset, isRequesting } = usePasswordReset();
 *
 * // Step 1: Request reset
 * await requestReset('user@example.com');
 *
 * // Step 2: User receives email with reset key
 *
 * // Step 3: Confirm with new password
 * await confirmReset(resetKey, newPassword);
 * ```
 */
export declare function usePasswordReset(): UsePasswordResetResult;
//# sourceMappingURL=usePasswordReset.d.ts.map