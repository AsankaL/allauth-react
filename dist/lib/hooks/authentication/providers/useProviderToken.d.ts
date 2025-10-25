import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, AuthenticationResponse, ProviderTokenRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for provider token authentication
 */
export declare function useProviderToken(): UseMutationResult<AuthenticatedResponse | AuthenticationResponse, ErrorResponse, ProviderTokenRequest>;
//# sourceMappingURL=useProviderToken.d.ts.map