import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, AuthenticationResponse, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for WebAuthn authentication
 */
export declare function useWebAuthnAuthenticate(): UseMutationResult<AuthenticatedResponse | AuthenticationResponse, ErrorResponse, string>;
//# sourceMappingURL=useWebAuthnAuthenticate.d.ts.map