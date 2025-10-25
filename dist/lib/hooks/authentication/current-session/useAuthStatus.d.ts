import { type UseQueryResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, NotAuthenticatedResponse } from '../../../api/types';
/**
 * Query hook for current authentication status
 */
export declare function useAuthStatus(): UseQueryResult<AuthenticatedResponse | NotAuthenticatedResponse>;
//# sourceMappingURL=useAuthStatus.d.ts.map