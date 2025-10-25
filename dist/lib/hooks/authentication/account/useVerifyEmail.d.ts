import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, AuthenticationResponse, EmailVerificationRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for verifying email address
 */
export declare function useVerifyEmail(): UseMutationResult<AuthenticatedResponse | AuthenticationResponse, ErrorResponse, EmailVerificationRequest>;
//# sourceMappingURL=useVerifyEmail.d.ts.map