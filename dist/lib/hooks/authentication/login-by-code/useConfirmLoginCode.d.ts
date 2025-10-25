import { type UseMutationResult } from '@tanstack/react-query';
import type { AuthenticatedResponse, AuthenticationResponse, ConfirmLoginCodeRequest, ErrorResponse } from '../../../api/types';
/**
 * Mutation hook for confirming a login code
 */
export declare function useConfirmLoginCode(): UseMutationResult<AuthenticatedResponse | AuthenticationResponse, ErrorResponse, ConfirmLoginCodeRequest>;
//# sourceMappingURL=useConfirmLoginCode.d.ts.map