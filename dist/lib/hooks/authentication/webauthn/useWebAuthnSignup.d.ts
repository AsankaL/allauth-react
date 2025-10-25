import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, AuthenticationResponse, WebAuthnSignupRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for WebAuthn signup
 */
export declare function useWebAuthnSignup(): UseMutationResult<AuthenticatedResponse | AuthenticationResponse, ErrorResponse, WebAuthnSignupRequest>;
//# sourceMappingURL=useWebAuthnSignup.d.ts.map