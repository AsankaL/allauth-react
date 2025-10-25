import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, AuthenticationResponse, PhoneVerificationRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for verifying phone number
 */
export declare function useVerifyPhone(): UseMutationResult<AuthenticatedResponse | AuthenticationResponse, ErrorResponse, PhoneVerificationRequest>;
//# sourceMappingURL=useVerifyPhone.d.ts.map