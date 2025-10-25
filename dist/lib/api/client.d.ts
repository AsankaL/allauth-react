import type { ClientType, StorageInterface, ConfigurationResponse, AuthenticatedResponse, AuthenticationResponse, NotAuthenticatedResponse, EmailAddressesResponse, EmailVerificationInfoResponse, PhoneNumberResponse, PasswordResetInfoResponse, ProviderAccountsResponse, ProviderSignupResponse, AuthenticatorsResponse, SensitiveRecoveryCodesAuthenticatorResponse, TOTPAuthenticatorResponse, NoTOTPAuthenticatorResponse, WebAuthnCredentialCreationOptions, WebAuthnCredentialRequestOptions, SessionsResponse, LoginRequest, SignupRequest, LoginByCodeRequest, ConfirmLoginCodeRequest, EmailVerificationRequest, PhoneVerificationRequest, PasswordResetRequest, PasswordResetConfirmRequest, PasswordChangeRequest, ReauthenticateRequest, EmailAddressRequest, EmailPrimaryRequest, ProviderTokenRequest, ProviderSignupRequest, MFAAuthenticateRequest, MFATrustRequest, TOTPActivateRequest, WebAuthnLoginRequest, WebAuthnSignupRequest, ProviderDisconnectRequest } from './types';
/**
 * AllauthClient provides methods to interact with the django-allauth headless API.
 * It supports both browser and app clients with automatic token management.
 */
export declare class AllauthClient {
    private storage;
    private csrfTokenUrl;
    private clientPath;
    private browserPath;
    constructor(apiBaseUrl?: string, csrfTokenEndpoint?: string, clientType?: ClientType, storage?: StorageInterface);
    private fetchCSRFToken;
    private fetch;
    private request;
    getConfiguration(): Promise<ConfigurationResponse>;
    getAuthenticationStatus(): Promise<AuthenticatedResponse | NotAuthenticatedResponse>;
    login(data: LoginRequest): Promise<AuthenticatedResponse | AuthenticationResponse>;
    logout(): Promise<NotAuthenticatedResponse>;
    signup(data: SignupRequest): Promise<AuthenticatedResponse | AuthenticationResponse>;
    reauthenticate(data: ReauthenticateRequest): Promise<AuthenticatedResponse>;
    requestLoginCode(data: LoginByCodeRequest): Promise<AuthenticationResponse>;
    confirmLoginCode(data: ConfirmLoginCodeRequest): Promise<AuthenticatedResponse | AuthenticationResponse>;
    listEmailAddresses(): Promise<EmailAddressesResponse>;
    addEmailAddress(data: EmailAddressRequest): Promise<EmailAddressesResponse>;
    removeEmailAddress(data: EmailAddressRequest): Promise<EmailAddressesResponse>;
    changePrimaryEmailAddress(data: EmailPrimaryRequest): Promise<EmailAddressesResponse>;
    requestEmailVerification(data: EmailAddressRequest): Promise<{
        status: 200;
    }>;
    getEmailVerificationInfo(key: string): Promise<EmailVerificationInfoResponse>;
    verifyEmail(data: EmailVerificationRequest): Promise<AuthenticatedResponse | AuthenticationResponse>;
    resendEmailVerification(): Promise<{
        status: 200;
    }>;
    getPhoneNumber(): Promise<PhoneNumberResponse>;
    updatePhoneNumber(phone: string): Promise<PhoneNumberResponse>;
    removePhoneNumber(): Promise<{
        status: 200;
    }>;
    verifyPhone(data: PhoneVerificationRequest): Promise<AuthenticatedResponse | AuthenticationResponse>;
    resendPhoneVerification(): Promise<{
        status: 200;
    }>;
    requestPassword(data: PasswordResetRequest): Promise<{
        status: 200;
    } | AuthenticationResponse>;
    getPasswordResetInfo(key: string): Promise<PasswordResetInfoResponse>;
    resetPassword(data: PasswordResetConfirmRequest): Promise<AuthenticatedResponse | AuthenticationResponse>;
    changePassword(data: PasswordChangeRequest): Promise<{
        status: 200;
    }>;
    listProviderAccounts(): Promise<ProviderAccountsResponse>;
    disconnectProviderAccount(data: ProviderDisconnectRequest): Promise<ProviderAccountsResponse>;
    providerRedirect(provider: string, callbackUrl: string, process?: 'login' | 'connect'): Promise<void>;
    providerToken(data: ProviderTokenRequest): Promise<AuthenticatedResponse | AuthenticationResponse>;
    getProviderSignup(): Promise<ProviderSignupResponse>;
    providerSignup(data: ProviderSignupRequest): Promise<AuthenticatedResponse | AuthenticationResponse>;
    listAuthenticators(): Promise<AuthenticatorsResponse>;
    getTOTPAuthenticator(): Promise<TOTPAuthenticatorResponse | NoTOTPAuthenticatorResponse>;
    activateTOTP(data: TOTPActivateRequest): Promise<TOTPAuthenticatorResponse>;
    deactivateTOTP(): Promise<{
        status: 200;
    }>;
    listRecoveryCodes(): Promise<SensitiveRecoveryCodesAuthenticatorResponse | {
        status: 404;
    }>;
    regenerateRecoveryCodes(): Promise<SensitiveRecoveryCodesAuthenticatorResponse>;
    mfaAuthenticate(data: MFAAuthenticateRequest): Promise<AuthenticatedResponse | AuthenticationResponse>;
    mfaReauthenticate(): Promise<AuthenticatedResponse>;
    mfaTrust(data: MFATrustRequest): Promise<AuthenticatedResponse>;
    getWebAuthnSignupOptions(): Promise<WebAuthnCredentialCreationOptions>;
    webAuthnSignup(data: WebAuthnSignupRequest): Promise<AuthenticatedResponse | AuthenticationResponse>;
    getWebAuthnLoginOptions(): Promise<WebAuthnCredentialRequestOptions>;
    webAuthnLogin(data: WebAuthnLoginRequest): Promise<AuthenticatedResponse | AuthenticationResponse>;
    getWebAuthnAuthenticateOptions(): Promise<WebAuthnCredentialRequestOptions>;
    webAuthnAuthenticate(credential: string): Promise<AuthenticatedResponse | AuthenticationResponse>;
    getWebAuthnReauthenticateOptions(): Promise<WebAuthnCredentialRequestOptions>;
    webAuthnReauthenticate(credential: string): Promise<AuthenticatedResponse>;
    listWebAuthnCredentials(): Promise<AuthenticatorsResponse>;
    deleteWebAuthnCredential(id: string): Promise<AuthenticatorsResponse>;
    listSessions(): Promise<SessionsResponse>;
    deleteSession(id?: number): Promise<SessionsResponse>;
}
export declare function initializeClient(config: {
    baseUrl?: string;
    csrfTokenEndpoint?: string;
    clientType?: ClientType;
    storage?: StorageInterface;
}): AllauthClient;
export declare function getClient(): AllauthClient;
//# sourceMappingURL=client.d.ts.map