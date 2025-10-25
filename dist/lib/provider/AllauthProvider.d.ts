import React from 'react';
import { QueryClient } from '@tanstack/react-query';
import type { ClientType, StorageInterface } from '../api/types';
interface AllauthProviderProps {
    clientType?: ClientType;
    baseUrl?: string;
    csrfTokenEndpoint?: string;
    storage?: StorageInterface;
    queryClient?: QueryClient;
    children: React.ReactNode;
}
export declare function AllauthProvider({ clientType, baseUrl, csrfTokenEndpoint, storage, queryClient, children, }: AllauthProviderProps): React.ReactElement;
export {};
//# sourceMappingURL=AllauthProvider.d.ts.map