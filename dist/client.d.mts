import * as react_jsx_runtime from 'react/jsx-runtime';
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
declare function UserProvider({ children }: {
    children: React.ReactNode;
}): react_jsx_runtime.JSX.Element;
declare function useUser(): Auth0ContextType;

export { UserProvider, useUser };
