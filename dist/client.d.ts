import React from 'react';
interface Auth0User {
    name?: string;
    email?: string;
    picture?: string;
    [key: string]: any;
}
interface Auth0ContextType {
    user: Auth0User | null;
    error: Error | null;
    isLoading: boolean;
}
export declare function UserProvider({ children }: {
    children: React.ReactNode;
}): import("react/jsx-runtime").JSX.Element;
export declare function useUser(): Auth0ContextType;
export {};
