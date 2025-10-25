import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, AuthenticationResponse, WebAuthnLoginRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for WebAuthn login
 */
export declare function useWebAuthnLogin(): UseMutationResult<AuthenticatedResponse | AuthenticationResponse, ErrorResponse, WebAuthnLoginRequest>;
//# sourceMappingURL=useWebAuthnLogin.d.ts.map