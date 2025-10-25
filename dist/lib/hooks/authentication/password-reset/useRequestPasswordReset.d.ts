import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticationResponse, PasswordResetRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for requesting a password reset
 */
export declare function useRequestPasswordReset(): UseMutationResult<{
    status: 200;
} | AuthenticationResponse, ErrorResponse, PasswordResetRequest>;
//# sourceMappingURL=useRequestPasswordReset.d.ts.map