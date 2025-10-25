import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, AuthenticationResponse, LoginRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for logging in with credentials
 */
export declare function useLogin(): UseMutationResult<AuthenticatedResponse | AuthenticationResponse, ErrorResponse, LoginRequest>;
//# sourceMappingURL=useLogin.d.ts.map