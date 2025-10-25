import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, AuthenticationResponse, PasswordResetConfirmRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for resetting password with key
 */
export declare function useResetPassword(): UseMutationResult<AuthenticatedResponse | AuthenticationResponse, ErrorResponse, PasswordResetConfirmRequest>;
//# sourceMappingURL=useResetPassword.d.ts.map