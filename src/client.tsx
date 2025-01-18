'use client';
import React, { createContext, useContext, useEffect, useState } from 'react';

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

const Auth0Context = createContext<Auth0ContextType>({
    user: null,
    error: null,
    isLoading: true,
});

export function UserProvider({ children }: { children: React.ReactNode }) {
    const [user, setUser] = useState<Auth0User | null>(null);
    const [error, setError] = useState<Error | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        async function loadUserFromAPI() {
            try {
                const res = await fetch('/api/auth/me');
                if (res.ok) {
                    const userData = await res.json() as any;
                    setUser(userData);
                }
            } catch (e) {
                setError(e instanceof Error ? e : new Error('An error occurred'));
            } finally {
                setIsLoading(false);
            }
        }

        loadUserFromAPI();
    }, []);

    return (
        <Auth0Context.Provider value={{ user, error, isLoading }}>
            {children}
        </Auth0Context.Provider>
    );
}

export function useUser() {
    return useContext(Auth0Context);
}

