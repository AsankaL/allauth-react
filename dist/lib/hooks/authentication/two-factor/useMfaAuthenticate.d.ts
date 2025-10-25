import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, AuthenticationResponse, MFAAuthenticateRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for MFA authentication
 */
export declare function useMfaAuthenticate(): UseMutationResult<AuthenticatedResponse | AuthenticationResponse, ErrorResponse, MFAAuthenticateRequest>;
//# sourceMappingURL=useMfaAuthenticate.d.ts.map