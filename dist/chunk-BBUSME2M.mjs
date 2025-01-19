// src/client.tsx
import { createContext, useContext, useEffect, useState } from "react";
import { jsx } from "react/jsx-runtime";
var Auth0Context = createContext({
  user: null,
  error: null,
  isLoading: true
});
function UserProvider({ children }) {
  const [user, setUser] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  useEffect(() => {
    async function loadUserFromAPI() {
      try {
        const res = await fetch("/api/auth/me");
        if (res.ok) {
          const userData = await res.json();
          setUser(userData);
        }
      } catch (e) {
        setError(e instanceof Error ? e : new Error("An error occurred"));
      } finally {
        setIsLoading(false);
      }
    }
    loadUserFromAPI();
  }, []);
  return /* @__PURE__ */ jsx(Auth0Context.Provider, { value: { user, error, isLoading }, children });
}
function useUser() {
  return useContext(Auth0Context);
}

export {
  UserProvider,
  useUser
};
