import { User } from "./types";

export const checkUserIsNoAuthUser = (userId: string) => {
  return userId === "__no_auth_user__";
};

export const getCurrentUser = async (): Promise<User | null> => {
  const response = await fetch("/api/me", {
    credentials: "include",
  });
  if (!response.ok) {
    return null;
  }
  const user = await response.json();
  return user;
};

export const logout = async (): Promise<Response> => {
  const response = await fetch("/api/auth/logout", {
    method: "POST",
    credentials: "include",
    redirect: "manual", // Don't follow redirects automatically
  });
  
  // Check if it's a redirect response (for OIDC logout)
  if (response.status === 307 || response.status === 302) {
    const location = response.headers.get("location");
    
    if (location) {
      // For OIDC logout, redirect the entire window to Keycloak logout
      window.location.href = location;
      // Return a special response to indicate OIDC redirect happened
      return new Response(null, { status: 204 }); // 204 = No Content, signals OIDC redirect
    }
  }
  
  return response;
};

export const basicLogin = async (
  email: string,
  password: string
): Promise<Response> => {
  const params = new URLSearchParams([
    ["username", email],
    ["password", password],
  ]);

  const response = await fetch("/api/auth/login", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params,
  });
  return response;
};

export const basicSignup = async (
  email: string,
  password: string,
  referralSource?: string
) => {
  const response = await fetch("/api/auth/register", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      username: email,
      password,
      referral_source: referralSource,
    }),
  });
  return response;
};
