import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for reauthentication
 */
export declare function useReauthenticate(): UseMutationResult<AuthenticatedResponse, ErrorResponse, {
    password: string;
}>;
//# sourceMappingURL=useReauthenticate.d.ts.map