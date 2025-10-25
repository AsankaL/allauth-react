import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, AuthenticationResponse, SignupRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for signing up new users
 */
export declare function useSignup(): UseMutationResult<AuthenticatedResponse | AuthenticationResponse, ErrorResponse, SignupRequest>;
//# sourceMappingURL=useSignup.d.ts.map