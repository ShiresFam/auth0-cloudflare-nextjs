"use strict";
"use client";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/client.tsx
var client_exports = {};
__export(client_exports, {
  UserProvider: () => UserProvider,
  useUser: () => useUser
});
module.exports = __toCommonJS(client_exports);
var import_react = require("react");
var import_jsx_runtime = require("react/jsx-runtime");
var Auth0Context = (0, import_react.createContext)({
  user: null,
  error: null,
  isLoading: true
});
function UserProvider({ children }) {
  const [user, setUser] = (0, import_react.useState)(null);
  const [error, setError] = (0, import_react.useState)(null);
  const [isLoading, setIsLoading] = (0, import_react.useState)(true);
  (0, import_react.useEffect)(() => {
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
  return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Auth0Context.Provider, { value: { user, error, isLoading }, children });
}
function useUser() {
  return (0, import_react.useContext)(Auth0Context);
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  UserProvider,
  useUser
});
