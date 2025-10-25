import { type UseMutationResult } from '@tanstack/react-query';
import type { EmailAddressRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for requesting email verification
 */
export declare function useRequestEmailVerification(): UseMutationResult<{
    status: 200;
}, ErrorResponse, EmailAddressRequest>;
//# sourceMappingURL=useRequestEmailVerification.d.ts.map