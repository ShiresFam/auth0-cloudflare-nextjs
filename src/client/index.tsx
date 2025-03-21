'use client';

import React, { createContext, useContext, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

interface Auth0User {
    sub: string;
    name?: string;
    email?: string;
    picture?: string;
    [key: string]: any;
}

interface Auth0ContextType {
    user: Auth0User | null;
    error: Error | null;
    isLoading: boolean;
    login: () => void;
    logout: () => void;
}

const Auth0Context = createContext<Auth0ContextType>({
    user: null,
    error: null,
    isLoading: true,
    login: () => undefined,
    logout: () => undefined,
});

export function UserProvider({ children }: { children: React.ReactNode }) {
    const [user, setUser] = useState<Auth0User | null>(null);
    const [error, setError] = useState<Error | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [isMounted, setIsMounted] = useState(false);
    const router = useRouter();

    useEffect(() => {
        setIsMounted(true);
        return () => setIsMounted(false);
    }, []);

    useEffect(() => {
        if (isMounted) {
            async function loadUserFromAPI() {
                try {
                    const res = await fetch('/api/auth/me', {
                        credentials: 'include',
                    });

                    const data: Auth0User = await res.json();

                    if (data.isAuthenticated && data.user) {
                        setUser(data.user);
                    } else {
                        // If not authenticated but we have a refresh token, try refreshing
                        const refreshToken = document.cookie.includes('refresh_token');
                        if (refreshToken) {
                            try {
                                const refreshRes = await fetch('/api/auth/refresh', {
                                    credentials: 'include',
                                });
                                if (refreshRes.ok) {
                                    // Retry loading user data
                                    loadUserFromAPI();
                                    return;
                                }
                            } catch (refreshError) {
                                console.error('Token refresh failed:', refreshError);
                            }
                        }
                        setUser(null);
                    }
                } catch (e) {
                    console.error('Auth check failed:', e);
                    setUser(null);
                } finally {
                    setIsLoading(false);
                }
            }

            loadUserFromAPI();
        }
    }, [isMounted]);

    const login = () => {
        if (isMounted) {
            router.push('/api/auth/login');
        }
    };

    const logout = () => {
        if (isMounted) {
            router.push('/api/auth/logout');
        }
    };

    if (!isMounted) {
        return null;
    }

    return (
        <Auth0Context.Provider value={{ user, error, isLoading, login, logout }}>
            {children}
        </Auth0Context.Provider>
    );
}

export function useUser() {
    const context = useContext(Auth0Context);
    if (context === undefined) {
        throw new Error('useUser must be used within a UserProvider');
    }
    return context;
}

